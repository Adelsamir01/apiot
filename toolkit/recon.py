"""recon.py — Reconnaissance wrappers around native Kali Linux tools."""

import subprocess
import xml.etree.ElementTree as ET


def scan_subnet(subnet: str = "192.168.100.10-50", interface: str | None = "br0") -> list[dict]:
    """Ping-sweep a subnet using nmap -sn. Returns list of discovered hosts.

    Uses --send-ip to force ICMP probes (required to detect bare-metal
    MCU devices that don't respond to ARP-only sweeps on the bridge).
    Default range covers the dnsmasq DHCP pool (.10-.50).

    Each host dict: {"ip": str, "mac": str | None, "vendor": str | None}
    """
    cmd = ["sudo", "nmap", "-sn", "-n", "--send-ip"]
    if interface:
        cmd += ["-e", interface]
    cmd += [subnet, "-oX", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"nmap scan failed: {result.stderr.strip()}")

    hosts = []
    root = ET.fromstring(result.stdout)
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip_el = host_el.find("address[@addrtype='ipv4']")
        mac_el = host_el.find("address[@addrtype='mac']")
        if ip_el is None:
            continue
        hosts.append({
            "ip": ip_el.get("addr"),
            "mac": mac_el.get("addr") if mac_el is not None else None,
            "vendor": mac_el.get("vendor") if mac_el is not None else None,
        })
    return hosts


def udp_probe(ip: str, ports: str = "5683", timing: str = "T4",
              interface: str | None = "br0") -> dict:
    """Quick UDP service scan on specific ports. Returns same format as fingerprint_target."""
    cmd = ["sudo", "nmap", "-sU", "-sV", "-n", f"-p{ports}", f"-{timing}"]
    if interface:
        cmd += ["-e", interface]
    cmd += ["-oX", "-", ip]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"nmap UDP probe failed: {result.stderr.strip()}")

    root = ET.fromstring(result.stdout)
    ports_map: dict = {}
    host_el = root.find("host")
    if host_el is not None:
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            svc_el = port_el.find("service")
            if state_el is None:
                continue
            port_num = int(port_el.get("portid"))
            ports_map[port_num] = {
                "state": state_el.get("state", "unknown"),
                "protocol": port_el.get("protocol", "udp"),
                "service": svc_el.get("name", "unknown") if svc_el is not None else "unknown",
                "version": svc_el.get("version", "") if svc_el is not None else "",
            }
    return {"ip": ip, "ports": ports_map}


def fingerprint_target(ip: str, ports: str = "1-65535", timing: str = "T3",
                       interface: str | None = "br0") -> dict:
    """Service-version scan a target. Returns structured fingerprint.

    Result dict: {
        "ip": str,
        "ports": {port_number: {"state": str, "protocol": str, "service": str, "version": str}},
        "os_guess": str | None,
    }
    """
    cmd = ["sudo", "nmap", "-sV", "-n", f"-p{ports}", f"-{timing}"]
    if interface:
        cmd += ["-e", interface]
    cmd += ["-oX", "-", ip]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"nmap fingerprint failed: {result.stderr.strip()}")

    root = ET.fromstring(result.stdout)
    fingerprint: dict = {"ip": ip, "ports": {}, "os_guess": None}

    host_el = root.find("host")
    if host_el is None:
        return fingerprint

    for port_el in host_el.findall(".//port"):
        state_el = port_el.find("state")
        svc_el = port_el.find("service")
        if state_el is None:
            continue
        port_num = int(port_el.get("portid"))
        fingerprint["ports"][port_num] = {
            "state": state_el.get("state", "unknown"),
            "protocol": port_el.get("protocol", "tcp"),
            "service": svc_el.get("name", "unknown") if svc_el is not None else "unknown",
            "version": svc_el.get("version", "") if svc_el is not None else "",
        }

    os_el = host_el.find(".//osmatch")
    if os_el is not None:
        fingerprint["os_guess"] = os_el.get("name")

    return fingerprint
