"""lab_bridge.py — Pre-flight checks for the IoT Virtual Lab.

Verifies that the iot_vlab REST API is reachable and has devices,
then runs the network mapper so the agent has reconnaissance data
from its first turn.

APIOT never starts, stops, or respawns iot_vlab.  The lab must be
launched manually before running the agent.
"""

import requests

from apiot.toolkit.lab_client import LabClient, LabOfflineError


LAB_API_URL = "http://localhost:5000"
LAB_HEALTH_RETRIES = 5
LAB_HEALTH_INTERVAL = 2  # seconds


def _is_lab_online() -> bool:
    """Quick health check against the lab API."""
    try:
        resp = requests.get(f"{LAB_API_URL}/api/ready", timeout=3)
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


def _is_lab_ready() -> bool:
    """Check if the lab is fully ready (all devices booted, no pending IPs)."""
    try:
        resp = requests.get(f"{LAB_API_URL}/api/ready", timeout=5)
        if resp.status_code != 200:
            return False
        data = resp.json()
        return data.get("ready", False)
    except Exception:
        return False


def _seed_topology_devices(topo: list[dict]) -> None:
    """Pre-populate network_state.json with devices known from /topology.

    The nmap mapper only sweeps .10-.50 but software simulators live at .100+.
    This seeds their IPs so the agent finds them via get_actionable_targets even
    when the mapper subnet sweep misses them.
    """
    from apiot.core.state import AgentMemory
    from apiot.core.mapper import classify
    import socket

    memory = AgentMemory()
    for dev in topo:
        ip = dev.get("ip") or dev.get("address")
        if not ip:
            continue
        ports_list = dev.get("ports", [])
        ports_dict = {}
        for p in ports_list:
            ports_dict[str(p)] = {"state": "open", "service": ""}

        open_ports = set(ports_list)
        cls = classify(open_ports, mac=None)

        fp = {
            "ip": ip,
            "ports": ports_dict,
            "os_guess": dev.get("arch", "Unknown"),
            "classification": cls,
            "source": "lab_topology",
        }
        memory.update_host(ip, {"mac": None, "vendor": dev.get("firmware_id", "sim")})
        memory.update_fingerprint(ip, fp)
        print(f"[Lab Bridge] Seeded topology device: {ip}  [{cls['category']}]  ports={sorted(open_ports)}")


def _run_mapper():
    """Run the APIOT network mapper to populate network_state.json."""
    print("[Lab Bridge] Running network mapper...")
    try:
        from apiot.core.mapper import run_mapper
        run_mapper()
        print("[Lab Bridge] Mapper complete. network_state.json updated.")
    except Exception as e:
        print(f"[Lab Bridge] Mapper failed (non-fatal): {e}")


def ensure_lab_ready():
    """Full pre-flight sequence. Call this before the agent loop.

    Checks that:
      1. iot_vlab REST API is reachable.
      2. Lab reports ready (all devices booted via /api/ready).
      3. At least one device is in the topology.
      4. Network mapper runs successfully.

    Raises SystemExit on any hard failure.
    """
    import time

    print("[Lab Bridge] Running pre-flight checks...")

    if not _is_lab_online():
        for i in range(LAB_HEALTH_RETRIES):
            time.sleep(LAB_HEALTH_INTERVAL)
            if _is_lab_online():
                break
            print(f"[Lab Bridge] Waiting for lab API... ({i + 1}/{LAB_HEALTH_RETRIES})")
        else:
            raise SystemExit(
                "[Lab Bridge] iot_vlab REST API is not reachable at "
                f"{LAB_API_URL}.\n"
                "Start it manually before running APIOT:\n"
                "  cd ../iot_vlab && sudo python3 interactive_lab.py"
            )

    print("[Lab Bridge] Lab API is online.")

    if not _is_lab_ready():
        print("[Lab Bridge] Waiting for lab to be fully ready (devices booting)...")
        for i in range(LAB_HEALTH_RETRIES * 3):
            time.sleep(LAB_HEALTH_INTERVAL)
            if _is_lab_ready():
                break
            print(f"[Lab Bridge] Devices still booting... ({i + 1})")
        else:
            print("[Lab Bridge] Warning: /api/ready did not return ready=true. Continuing with /topology fallback.")

    lab = LabClient(base_url=LAB_API_URL)
    topo = lab.get_topology()
    if not topo:
        raise SystemExit(
            "[Lab Bridge] Lab has no devices.\n"
            "Spawn targets manually via the iot_vlab API or interactive wizard,\n"
            "then re-run APIOT."
        )

    print(f"[Lab Bridge] Lab has {len(topo)} device(s). All ready.")

    # Run mapper first (it clears memory), then seed topology devices.
    # Seeding after ensures simulator IPs (.100+) survive the mapper's clear().
    _run_mapper()
    _seed_topology_devices(topo)
    print("[Lab Bridge] Pre-flight complete. Ready for agent loop.\n")
