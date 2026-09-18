#!/usr/bin/env python3
"""visualize.py — ASCII table renderer for the network map.

Reads data/network_state.json and prints a human-readable summary.

Run:  python3 -m apiot.toolkit.visualize   (from llm_iot/)
  or: python3 apiot/toolkit/visualize.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apiot.core.state import AgentMemory


def render(memory: AgentMemory | None = None) -> str:
    """Build and return an ASCII table of the current network map."""
    mem = memory or AgentMemory()
    ctx = mem.get_full_context()
    hosts = ctx.get("discovered_hosts", {})
    fingerprints = ctx.get("fingerprints", {})

    # Column definitions
    cols = [
        ("IP Address", 18),
        ("MAC", 19),
        ("Open Ports", 20),
        ("OS / Stack", 22),
        ("Category", 24),
        ("Attack Surface", 30),
    ]

    header = "  ".join(name.ljust(width) for name, width in cols)
    sep = "  ".join("-" * width for _, width in cols)
    lines = [header, sep]

    # Merge host + fingerprint data, sort by IP
    all_ips = sorted(set(hosts.keys()) | set(fingerprints.keys()))

    for ip in all_ips:
        host = hosts.get(ip, {})
        fp = fingerprints.get(ip, {})
        cls = fp.get("classification", {})
        ports_map = fp.get("ports", {})
        open_ports = sorted(int(p) for p, info in ports_map.items()
                            if isinstance(info, dict) and info.get("state") in ("open", "open|filtered"))

        row = [
            ip.ljust(cols[0][1]),
            (host.get("mac") or "—").ljust(cols[1][1]),
            (", ".join(str(p) for p in open_ports) or "—").ljust(cols[2][1]),
            (cls.get("os_guess") or fp.get("os_guess") or "—").ljust(cols[3][1]),
            (cls.get("category") or "—").ljust(cols[4][1]),
            (", ".join(cls.get("attack_surface", [])) or "—").ljust(cols[5][1]),
        ]
        lines.append("  ".join(row))

    if len(lines) == 2:
        lines.append("  (no targets mapped — run mapper.py first)")

    return "\n".join(lines)


def main():
    print()
    print("=" * 100)
    print("  APIOT Network Map")
    print("=" * 100)
    print()
    print(render())
    print()


if __name__ == "__main__":
    main()
