#!/usr/bin/env python3
"""mapper.py — Autonomous network mapper (the "Scout").

Systematically discovers, fingerprints, and categorizes every device
on all lab subnets using Phase 1 recon tools, then persists enriched
results into AgentMemory.

Run:  sudo python3 -m apiot.core.mapper   (from llm_iot/)
  or: sudo python3 apiot/core/mapper.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apiot.toolkit.recon import scan_subnet, fingerprint_target, udp_probe
from apiot.core.state import AgentMemory

SUBNETS = [
    {"range": "192.168.100.10-50", "interface": "br0", "gateway": "192.168.100.1"},
    {"range": "192.168.200.10-50", "interface": "br_internal", "gateway": "192.168.200.1"},
]

SCAN_PORTS = "22,23,80,443,502,4242,5683"
UDP_PORTS = "5683"

# ── Heuristic classification ─────────────────────────────────────────
#
# Bare-Metal OT Sensor (Zephyr RTOS / Cortex-M3)
#   - Exposes exactly ONE of: 502, 4242, 5683
#   - Does NOT expose IT ports (22, 23, 80, 443)
#   - MAC is always 00:00:94:00:83:00 (Stellaris hardcoded)
#
# Linux Gateway/Router (MIPS or ARM)
#   - Exposes SSH (22) and/or HTTP (80)
#   - May have a random QEMU-range MAC (52:54:00:xx:xx:xx)

OT_PORTS = {502, 4242, 5683}
IT_PORTS = {22, 23, 80, 443}
STELLARIS_MAC = "00:00:94:00:83:00"


def classify(open_ports: set[int], mac: str | None) -> dict:
    """Return a category dict based on open ports and MAC address."""
    has_ot = bool(open_ports & OT_PORTS)
    has_it = bool(open_ports & IT_PORTS)

    if has_ot and not has_it:
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
            surface.append("brute_force_ssh")
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

    return {
        "category": "Unknown",
        "os_guess": "Unknown",
        "arch_guess": "Unknown",
        "role": "Unclassified",
        "attack_surface": [],
    }


class NetworkMapper:
    """Orchestrates recon tools to build a full network map across all subnets."""

    def __init__(self, subnets: list[dict] | None = None, memory: AgentMemory | None = None):
        self.subnets = subnets or SUBNETS
        self.memory = memory or AgentMemory()

    def run(self) -> dict:
        """Execute the full mapping pipeline. Returns the enriched state."""
        self.memory.clear()
        total_hosts = []
        for sub in self.subnets:
            print(f"[mapper] Sweeping {sub['range']} on {sub['interface']} ...")
            hosts = self._sweep(sub)
            print(f"[mapper] Found {len(hosts)} live host(s) on {sub['interface']}, fingerprinting ...")
            for h in hosts:
                self._deep_scan(h, sub["interface"])
            total_hosts.extend(hosts)

        ctx = self.memory.get_full_context()
        n = len(ctx["fingerprints"])
        print(f"[mapper] Mapping complete — {n} target(s) categorized across {len(self.subnets)} subnet(s).")
        return ctx

    def _sweep(self, sub: dict) -> list[dict]:
        """Ping-sweep a single subnet."""
        hosts = scan_subnet(sub["range"], interface=sub["interface"])
        for h in hosts:
            self.memory.update_host(h["ip"], {"mac": h["mac"], "vendor": h["vendor"]})
        return [h for h in hosts if h["ip"] != sub["gateway"]]

    def _deep_scan(self, host: dict, interface: str) -> None:
        """Fingerprint (TCP+UDP), classify, and persist."""
        ip = host["ip"]
        try:
            fp = fingerprint_target(ip, ports=SCAN_PORTS, timing="T4", interface=interface)
        except Exception as e:
            print(f"[mapper] WARNING: TCP fingerprint failed for {ip}: {e}")
            fp = {"ip": ip, "ports": {}, "os_guess": None, "scan_error": str(e)}

        try:
            udp = udp_probe(ip, ports=UDP_PORTS, timing="T4", interface=interface)
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


def run_mapper(subnets: list[dict] | None = None) -> dict:
    """Convenience entry point used by lab_bridge and CLI."""
    return NetworkMapper(subnets=subnets).run()


if __name__ == "__main__":
    run_mapper()
