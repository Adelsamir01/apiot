#!/usr/bin/env python3
"""dumb_fuzzer.py — Random fuzzer baseline for stealth comparison.

Sends random UDP/TCP garbage at targets. Measures packets-sent vs success.
Used to compare against the LLM-driven agent's PPV (Contribution IV).
"""

import argparse
import random
import socket
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apiot.toolkit.verifier import verify_crash


def random_bytes(min_len: int = 4, max_len: int = 256) -> bytes:
    """Generate random packet payload."""
    n = random.randint(min_len, max_len)
    return bytes(random.randint(0, 255) for _ in range(n))


def udp_fuzz(ip: str, port: int, count: int, timeout: float = 2.0) -> dict:
    """Send random UDP packets. Return packets_sent and whether target crashed."""
    sent = 0
    for _ in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(random_bytes(), (ip, port))
                sent += 1
        except OSError:
            sent += 1
    return {"packets_sent": sent, "target": f"{ip}:{port}"}


def tcp_fuzz(ip: str, port: int, count: int, timeout: float = 2.0) -> dict:
    """Send random TCP payloads. Return packets_sent."""
    sent = 0
    for _ in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(random_bytes())
                sent += 1
        except (ConnectionRefusedError, ConnectionResetError, OSError, socket.timeout):
            sent += 1
    return {"packets_sent": sent, "target": f"{ip}:{port}"}


def run_baseline(ip: str, ports: list[tuple[int, str]], max_packets: int = 1000) -> dict:
    """Fuzz target with random packets. Check for crash after each batch."""
    total_sent = 0
    batch = 50

    for port, proto in ports:
        for _ in range(max_packets // batch):
            if proto == "udp":
                r = udp_fuzz(ip, port, batch)
            else:
                r = tcp_fuzz(ip, port, batch)
            total_sent += r["packets_sent"]

            vr = verify_crash(ip, known_ports=[port], timeout=5.0)
            if vr.get("verified"):
                return {
                    "success": True,
                    "packets_sent": total_sent,
                    "ppv": total_sent,
                    "target": ip,
                    "port": port,
                }

    return {
        "success": False,
        "packets_sent": total_sent,
        "ppv": None,
        "target": ip,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Target IP")
    parser.add_argument("--ports", default="5683:udp,502:tcp", help="Comma-separated port:proto")
    parser.add_argument("--max-packets", type=int, default=1000)
    args = parser.parse_args()

    ports = []
    for item in args.ports.split(","):
        if ":" in item:
            p, proto = item.strip().split(":")
            ports.append((int(p), proto.strip().lower()))
        else:
            ports.append((int(item.strip()), "tcp"))

    result = run_baseline(args.ip, ports, args.max_packets)
    print(f"Packets sent: {result['packets_sent']}")
    print(f"Success: {result['success']}")
    if result.get("ppv"):
        print(f"PPV (baseline): {result['ppv']}")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
