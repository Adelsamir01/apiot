#!/usr/bin/env python3
"""mapper.py — Autonomous network mapper (the "Scout").

Systematically discovers, fingerprints, and categorizes every device
on the lab subnet using Phase 1 recon tools, then persists enriched
results into AgentMemory.

Run:  sudo python3 -m apiot.core.mapper   (from llm_iot/)
  or: sudo python3 apiot/core/mapper.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apiot.toolkit.recon import scan_subnet, fingerprint_target, udp_probe
from apiot.core.state import AgentMemory

# Gateway IP is the host itself — skip fingerprinting it
GATEWAY_IP = "192.168.100.1"

# Ports that fingerprint_target will probe (covers every known lab service)
SCAN_PORTS = "22,23,80,443,502,4242,5683"
UDP_PORTS = "5683"

# ── Heuristic classification ─────────────────────────────────────────
#
# The lab has two device classes that are distinguishable purely from
# their network fingerprint:
#
#   Bare-Metal OT Sensor (Zephyr RTOS / Cortex-M3)
#     - Exposes exactly ONE of: 502, 4242, 5683
#     - Does NOT expose IT ports (22, 23, 80, 443)
#     - MAC is always 00:00:94:00:83:00 (Stellaris hardcoded)
#
#   Linux Gateway/Router (MIPS or ARM)
#     - Exposes SSH (22) and/or HTTP (80)
#     - May have a random QEMU-range MAC (52:54:00:xx:xx:xx)

OT_PORTS = {502, 4242, 5683}
IT_PORTS = {22, 23, 80, 443}
STELLARIS_MAC = "00:00:94:00:83:00"


def classify(open_ports: set[int], mac: str | None) -> dict:
    """Return a category dict based on open ports and MAC address.

    Returns:
        {"category": str, "os_guess": str, "arch_guess": str, "attack_surface": list[str]}
    """
    has_ot = bool(open_ports & OT_PORTS)
    has_it = bool(open_ports & IT_PORTS)

    if has_ot and not has_it:
        # Determine specific OT sub-type from the port
        if 502 in open_ports:
            role = "PLC / Modbus Controller"
            surface = ["modbus_write_coil", "modbus_mbap_overflow"]
        elif 5683 in open_ports:
            role = "CoAP Sensor / Smart Meter"
            surface = ["coap_option_overflow"]
        else:
            role = "Echo Sensor"
            surface = ["tcp_echo_probe"]

        return {
            "category": "Bare-Metal OT Sensor",
            "os_guess": "Zephyr RTOS",
            "arch_guess": "ARM Cortex-M3" if mac and mac.upper() == STELLARIS_MAC.upper() else "Unknown MCU",
            "role": role,
            "attack_surface": surface,
        }

    if has_it:
        surface = []
        if 22 in open_ports:
            surface.append("ssh_brute_force")
        if 23 in open_ports:
            surface.append("brute_force_telnet")
        if 80 in open_ports or 443 in open_ports:
            surface.append("http_cmd_injection")

        return {
            "category": "Linux Gateway/Router",
            "os_guess": "Linux (Debian-based)",
            "arch_guess": "MIPS or ARM",
            "role": "IoT Gateway",
            "attack_surface": surface,
        }

    # Ambiguous — has both OT and IT ports, or none
    return {
        "category": "Unknown",
        "os_guess": "Unknown",
        "arch_guess": "Unknown",
        "role": "Unclassified",
        "attack_surface": [],
    }


class NetworkMapper:
    """Orchestrates recon tools to build a full network map."""

    def __init__(self, subnet: str = "192.168.100.10-50", memory: AgentMemory | None = None):
        self.subnet = subnet
        self.memory = memory or AgentMemory()

    def run(self) -> dict:
        """Execute the full mapping pipeline. Returns the enriched state."""
        self.memory.clear()
        print(f"[mapper] Sweeping {self.subnet} ...")
        hosts = self._sweep()
        print(f"[mapper] Found {len(hosts)} live host(s), fingerprinting ...")
        for h in hosts:
            self._deep_scan(h)
        ctx = self.memory.get_full_context()
        n = len(ctx["fingerprints"])
        print(f"[mapper] Mapping complete — {n} target(s) categorized.")
        return ctx

    def _sweep(self) -> list[dict]:
        """Step 1: Ping-sweep the subnet."""
        hosts = scan_subnet(self.subnet)
        for h in hosts:
            self.memory.update_host(h["ip"], {"mac": h["mac"], "vendor": h["vendor"]})
        return [h for h in hosts if h["ip"] != GATEWAY_IP]

    def _deep_scan(self, host: dict) -> None:
        """Steps 2-4: Fingerprint (TCP+UDP), classify, and persist."""
        ip = host["ip"]
        try:
            fp = fingerprint_target(ip, ports=SCAN_PORTS, timing="T4")
        except Exception as e:
            print(f"[mapper] WARNING: TCP fingerprint failed for {ip}: {e}")
            fp = {"ip": ip, "ports": {}, "os_guess": None, "scan_error": str(e)}

        # UDP probe for CoAP and other datagram services
        try:
            udp = udp_probe(ip, ports=UDP_PORTS, timing="T4")
            for port, info in udp["ports"].items():
                if info["state"] in ("open", "open|filtered"):
                    fp["ports"][port] = info
        except Exception as e:
            print(f"[mapper] WARNING: UDP probe failed for {ip}: {e}")

        open_ports = {int(p) for p, info in fp["ports"].items()
                      if info["state"] in ("open", "open|filtered")}
        tag = classify(open_ports, host.get("mac"))

        fp["classification"] = tag
        self.memory.update_fingerprint(ip, fp)
        print(f"  {ip:>18s}  [{tag['category']}]  ports={sorted(open_ports)}  -> {tag['role']}")


if __name__ == "__main__":
    mapper = NetworkMapper()
    mapper.run()
