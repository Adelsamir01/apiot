"""verifier_blue.py — Blue team regression verifier (Purple Teaming).

After a virtual patch is applied, this module:
  1. Replays the exact raw payload that triggered the original crash.
  2. Asserts the sensor SURVIVES (patch blocks the attack).
  3. Updates network_state.json with remediation_status.

EXT7: Redesigned from named-exploit replay to raw-payload replay.
The agent passes the exact payload_hex it used to trigger the crash,
removing the dependency on a hardcoded REPLAY_TOOLS dict.

APIOT does not respawn or control lab devices.
"""

import time

from apiot.toolkit.protocol_tools import tcp_send, udp_send
from apiot.toolkit import verifier
from apiot.core.state import AgentMemory
from apiot.core.attack_log import AttackLogger


def replay_attack(target_ip: str, protocol: str, port: int,
                  payload_hex: str) -> dict:
    """Replay the exact bytes that previously crashed the target.

    The agent supplies the same payload_hex it used in the original exploit.
    This is more accurate than named-exploit replay because it tests the
    exact bytes the patch must block.

    protocol : "udp" for CoAP, "tcp" for Modbus
    """
    if protocol.lower() == "udp":
        result = udp_send(target_ip, port, payload_hex, timeout=5.0)
    else:
        result = tcp_send(target_ip, port, payload_hex, timeout=5.0)

    logger = AttackLogger()
    logger.log(
        target_ip=target_ip, target_arch="unknown",
        tool_used="replay_probe",
        payload_hex=payload_hex,
        packets_sent=1, outcome="replay_delivered",
        details=result,
    )
    return result


def verify_patch_holds(target_ip: str, known_ports: list[int] | None = None,
                       wait_before: float = 3.0) -> dict:
    """After replay, confirm the sensor is STILL ALIVE (patch blocked the attack)."""
    time.sleep(wait_before)

    if known_ports is None:
        known_ports = [502, 4242, 5683]

    result = verifier.verify_crash(target_ip, known_ports=known_ports, timeout=8.0)
    if result["verified"]:
        return {"patch_holds": False, "sensor_alive": False,
                "details": "Sensor crashed after replay — patch FAILED"}

    return {"patch_holds": True, "sensor_alive": True,
            "details": "Sensor survived replay — patch VERIFIED"}


def mark_remediated(vuln_id: str, target_ip: str, attack_description: str,
                    rule: str) -> None:
    """Update network_state.json with VERIFIED_SECURE status."""
    memory = AgentMemory()
    state = memory.get_full_context()
    vulns = state.get("active_vulnerabilities", {})
    if vuln_id in vulns:
        vulns[vuln_id]["remediation_status"] = "VERIFIED_SECURE"
        vulns[vuln_id]["patch_rule"] = rule
        vulns[vuln_id]["remediated_at"] = time.time()
    else:
        vulns[vuln_id] = {
            "ip": target_ip,
            "attack": attack_description,
            "remediation_status": "VERIFIED_SECURE",
            "patch_rule": rule,
            "remediated_at": time.time(),
        }
    memory._state["active_vulnerabilities"] = vulns
    memory._save()
