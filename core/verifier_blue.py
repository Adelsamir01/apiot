"""verifier_blue.py — Blue team regression verifier (Purple Teaming).

After a virtual patch is applied, this module:
  1. Confirms the sensor is back online (respawn if needed).
  2. Replays the exact Red Agent payload.
  3. Asserts the sensor SURVIVES (patch blocks the attack).
  4. Updates network_state.json with remediation_status.
"""

import time

from apiot.toolkit.lab_client import LabClient
from apiot.toolkit import ot_exploits, verifier
from apiot.core.state import AgentMemory
from apiot.core.attack_log import AttackLogger


REPLAY_TOOLS = {
    "coap_option_overflow": lambda ip: ot_exploits.coap_option_overflow(ip, port=5683),
    "modbus_mbap_overflow": lambda ip: ot_exploits.modbus_mbap_overflow(ip, port=502),
    "modbus_write_coil": lambda ip: ot_exploits.modbus_write_coil(ip, port=502, action="off"),
}


def ensure_sensor_online(sensor_firmware: str, lab: LabClient,
                         wait: int = 15) -> dict:
    """Make sure the target sensor is running. Respawn if crashed."""
    topo = lab.get_topology()
    for d in topo:
        if d["firmware_id"] == sensor_firmware and d["alive"]:
            return {"status": "already_online", "ip": d["ip"], "run_id": d["id"]}

    # Kill any stale instance
    for d in topo:
        if d["firmware_id"] == sensor_firmware:
            lab.kill_device(d["id"])
    time.sleep(1)

    result = lab.spawn_device(sensor_firmware)
    run_id = result["run_id"]
    print(f"[blue] Respawned {sensor_firmware} (run_id={run_id}), waiting {wait}s...")
    time.sleep(wait)

    topo = lab.get_topology()
    for d in topo:
        if d["id"] == run_id:
            return {"status": "respawned", "ip": d["ip"], "run_id": run_id}
    return {"status": "spawn_failed", "ip": None, "run_id": run_id}


def replay_attack(attack_name: str, target_ip: str) -> dict:
    """Fire the same exploit that previously succeeded."""
    fn = REPLAY_TOOLS.get(attack_name)
    if fn is None:
        return {"replayed": False, "error": f"No replay function for {attack_name}"}

    result = fn(target_ip)
    # Log replay in attack log
    logger = AttackLogger()
    logger.log(
        target_ip=target_ip, target_arch="ARM Cortex-M3",
        tool_used=f"replay_{attack_name}",
        payload_hex=result.get("payload_hex", ""),
        packets_sent=1, outcome="replay_delivered",
        details=result,
    )
    return result


def verify_patch_holds(target_ip: str, known_ports: list[int] | None = None,
                       wait_before: float = 3.0) -> dict:
    """After replay, confirm the sensor is STILL ALIVE (patch blocked it).

    Uses verify_crash (which includes UDP CoAP probes) and inverts the logic:
    if the sensor is NOT crashed, the patch held.
    """
    time.sleep(wait_before)

    if known_ports is None:
        known_ports = [502, 4242, 5683]

    result = verifier.verify_crash(target_ip, known_ports=known_ports, timeout=8.0)
    if result["verified"]:
        return {"patch_holds": False, "sensor_alive": False,
                "details": "Sensor crashed after replay — patch FAILED"}

    return {"patch_holds": True, "sensor_alive": True,
            "details": "Sensor survived replay — patch VERIFIED"}


def mark_remediated(vuln_id: str, target_ip: str, attack_name: str,
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
            "attack": attack_name,
            "remediation_status": "VERIFIED_SECURE",
            "patch_rule": rule,
            "remediated_at": time.time(),
        }
    memory._state["active_vulnerabilities"] = vulns
    memory._save()
