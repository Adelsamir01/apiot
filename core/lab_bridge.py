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
        resp = requests.get(f"{LAB_API_URL}/topology", timeout=3)
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


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
      2. At least one device is in the topology.
      3. Network mapper runs successfully.

    Raises SystemExit on any hard failure.
    """
    print("[Lab Bridge] Running pre-flight checks...")

    if not _is_lab_online():
        import time
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
                "  cd ../iot_vlab && sudo python3 lab_api.py"
            )

    print("[Lab Bridge] Lab API is online.")

    lab = LabClient(base_url=LAB_API_URL)
    topo = lab.get_topology()
    if not topo:
        raise SystemExit(
            "[Lab Bridge] Lab has no devices.\n"
            "Spawn targets manually via the iot_vlab API or interactive wizard,\n"
            "then re-run APIOT."
        )

    print(f"[Lab Bridge] Lab has {len(topo)} device(s).")

    _run_mapper()
    print("[Lab Bridge] Pre-flight complete. Ready for agent loop.\n")
