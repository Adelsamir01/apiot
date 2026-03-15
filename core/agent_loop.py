#!/usr/bin/env python3
"""agent_loop.py — Tool harness for the LLM Agent.

This module does NOT contain reasoning logic. It exposes cmd_* functions
that the dispatcher routes to from LLM tool calls, and a minimal CLI
interface for manual testing without the full agent.

EXT7: Replaced TOOLS dict + cmd_attack + cmd_analyze_attacks + cmd_apply_patch
with 8 protocol primitive cmd_* functions that route to the new toolkit modules.

Commands (manual CLI):
    get_state           Print current network_state.json
    get_targets         Print actionable targets
    stealth_check <ip>  Measure packet loss
    verify_crash <ip>   Check if target has crashed
    verify_shell <ip> [port]  Check for shell access
    log_summary         Print attack log metrics
    reset_logs          Clear attack_log.json and vulnerabilities
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
from apiot.toolkit import verifier


def _out(data):
    """Print structured JSON to stdout for the LLM to parse."""
    print(json.dumps(data, indent=2, default=str))


# ── Reconnaissance ────────────────────────────────────────────────────────────

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
    targets.sort(key=lambda t: 0 if t.get("category") == "Bare-Metal OT Sensor" else 1)
    return {"targets": targets}


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


# ── Red Team — Protocol Primitives ────────────────────────────────────────────

def cmd_coap_send(ip: str, port: int = 5683, ver: int = 1, msg_type: int = 0,
                  code: int = 1, msg_id: int = 0x1234, token_hex: str = "",
                  options_hex: str = "", payload_hex: str = "",
                  timeout: float = 5.0) -> dict:
    """Send a CoAP datagram and log to attack_log."""
    from apiot.toolkit.protocol_tools import coap_send
    result = coap_send(ip=ip, port=port, ver=ver, msg_type=msg_type, code=code,
                       msg_id=msg_id, token_hex=token_hex, options_hex=options_hex,
                       payload_hex=payload_hex, timeout=timeout)

    memory = AgentMemory()
    ctx = memory.get_full_context()
    arch = ctx.get("fingerprints", {}).get(ip, {}).get("classification", {}).get("arch_guess", "Unknown")
    logger = AttackLogger()
    logger.log(
        target_ip=ip, target_arch=arch, tool_used="coap_send",
        payload_hex=result.get("sent_hex", ""),
        packets_sent=1, outcome="delivered", details=result,
    )
    return result


def cmd_modbus_request(ip: str, port: int = 502, function_code: int = 0x03,
                       data_hex: str = "00 00 00 01", unit_id: int = 1,
                       transaction_id: int = 1, claimed_length: int | None = None,
                       timeout: float = 5.0) -> dict:
    """Send a Modbus request and log to attack_log."""
    from apiot.toolkit.protocol_tools import modbus_request
    result = modbus_request(ip=ip, port=port, function_code=function_code,
                            data_hex=data_hex, unit_id=unit_id,
                            transaction_id=transaction_id,
                            claimed_length=claimed_length, timeout=timeout)

    memory = AgentMemory()
    ctx = memory.get_full_context()
    arch = ctx.get("fingerprints", {}).get(ip, {}).get("classification", {}).get("arch_guess", "Unknown")
    logger = AttackLogger()
    logger.log(
        target_ip=ip, target_arch=arch, tool_used="modbus_request",
        payload_hex=result.get("sent_hex", ""),
        packets_sent=1, outcome="delivered", details=result,
    )
    return result


def cmd_tcp_send(ip: str, port: int, payload_hex: str,
                 timeout: float = 5.0) -> dict:
    """Send raw TCP bytes and log to attack_log."""
    from apiot.toolkit.protocol_tools import tcp_send
    result = tcp_send(ip=ip, port=port, payload_hex=payload_hex, timeout=timeout)

    logger = AttackLogger()
    logger.log(
        target_ip=ip, target_arch="Unknown", tool_used="tcp_send",
        payload_hex=result.get("sent_hex", ""),
        packets_sent=1, outcome="delivered", details=result,
    )
    return result


def cmd_udp_send(ip: str, port: int, payload_hex: str,
                 timeout: float = 5.0) -> dict:
    """Send raw UDP bytes and log to attack_log."""
    from apiot.toolkit.protocol_tools import udp_send
    result = udp_send(ip=ip, port=port, payload_hex=payload_hex, timeout=timeout)

    logger = AttackLogger()
    logger.log(
        target_ip=ip, target_arch="Unknown", tool_used="udp_send",
        payload_hex=result.get("sent_hex", ""),
        packets_sent=1, outcome="delivered", details=result,
    )
    return result


# ── Verification ─────────────────────────────────────────────────────────────

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


# ── Blue Team — Defensive Primitives ─────────────────────────────────────────

def cmd_iptables_rule(chain: str = "FORWARD", protocol: str = "tcp",
                      dport: int = 502, match_type: str = "plain",
                      match_value: str = "", algo: str = "bm",
                      verdict: str = "DROP", op: str = "add") -> dict:
    """Add or remove an iptables rule."""
    from apiot.toolkit.defense_primitives import iptables_rule
    return iptables_rule(chain=chain, protocol=protocol, dport=dport,
                         match_type=match_type, match_value=match_value,
                         algo=algo, verdict=verdict, op=op)


def cmd_protocol_block(protocol: str, dport: int,
                       direction: str = "both") -> dict:
    """Block all traffic to a port."""
    from apiot.toolkit.defense_primitives import protocol_block
    return protocol_block(protocol=protocol, dport=dport, direction=direction)


def cmd_modbus_fc_filter(function_code: int, dport: int = 502,
                         chain: str = "FORWARD") -> dict:
    """Drop Modbus packets with a specific Function Code."""
    from apiot.toolkit.defense_primitives import modbus_fc_filter
    return modbus_fc_filter(function_code=function_code, dport=dport, chain=chain)


def cmd_coap_rate_limit(dport: int = 5683, rate: str = "10/sec",
                        burst: int = 20, chain: str = "FORWARD") -> dict:
    """Rate-limit CoAP traffic."""
    from apiot.toolkit.defense_primitives import coap_rate_limit
    return coap_rate_limit(dport=dport, rate=rate, burst=burst, chain=chain)


def cmd_verify_patch(target_ip: str, protocol: str, port: int,
                     payload_hex: str) -> dict:
    """Replay raw payload and confirm patch holds (target survives)."""
    from apiot.core.verifier_blue import replay_attack, verify_patch_holds, mark_remediated
    replay_result = replay_attack(target_ip, protocol, port, payload_hex)
    patch_result = verify_patch_holds(target_ip)

    if patch_result["patch_holds"]:
        vuln_id = hashlib.md5(f"{target_ip}:{protocol}:{port}:patched".encode()).hexdigest()[:12]
        rule_info = f"patch_{protocol}_{port}"
        mark_remediated(vuln_id, target_ip, f"replay_{protocol}_{port}", rule_info)
        patch_result["vulnerability_id"] = vuln_id
        patch_result["remediation_status"] = "VERIFIED_SECURE"

    return {
        "replay": replay_result,
        "verification": patch_result,
    }


def cmd_list_patches() -> dict:
    """List current iptables FORWARD chain rules."""
    from apiot.toolkit.defender import list_forward_rules
    rules = list_forward_rules()
    return {"rules": rules, "count": len(rules)}


# ── Linux target utilities ────────────────────────────────────────────────────

def cmd_remote_exec(ip: str, command: str, creds: str = "root:root",
                    timeout: int = 30) -> dict:
    """Execute a command on a compromised target via SSH using sshpass."""
    user, passwd = creds.split(":", 1)
    try:
        result = subprocess.run(
            [
                "sshpass", f"-p{passwd}",
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", f"ConnectTimeout={min(timeout, 30)}",
                f"{user}@{ip}", command,
            ],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout[:8000],
            "stderr": result.stderr[:2000],
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": "sshpass not installed — run: apt install sshpass"}
    except Exception as e:
        return {"error": str(e)}


# ── Misc ─────────────────────────────────────────────────────────────────────

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


# ── Manual CLI ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        _out({
            "usage": "python3 -m apiot.core.agent_loop <command> [args]",
            "commands": {
                "get_state": "Print full network state",
                "get_targets": "List actionable targets",
                "stealth_check <ip>": "Measure packet loss",
                "verify_crash <ip>": "Check if target crashed",
                "verify_shell <ip> [port]": "Check shell access",
                "log_summary": "Print attack metrics",
                "reset_logs": "Clear attack log and vulnerabilities",
            },
        })
        return

    cmd = sys.argv[1]

    if cmd == "get_state":
        _out(cmd_get_state())
    elif cmd == "get_targets":
        _out(cmd_get_targets())
    elif cmd == "stealth_check" and len(sys.argv) >= 3:
        _out(cmd_stealth_check(sys.argv[2]))
    elif cmd == "verify_crash" and len(sys.argv) >= 3:
        _out(cmd_verify_crash(sys.argv[2]))
    elif cmd == "verify_shell" and len(sys.argv) >= 3:
        port = int(sys.argv[3]) if len(sys.argv) >= 4 else 23
        _out(cmd_verify_shell(sys.argv[2], port))
    elif cmd == "log_summary":
        _out(cmd_log_summary())
    elif cmd == "reset_logs":
        _out(cmd_reset_logs())
    else:
        _out({"error": f"Unknown command: {cmd}", "hint": "Run without args for usage"})


if __name__ == "__main__":
    main()
