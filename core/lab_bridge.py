"""lab_bridge.py — Pre-flight orchestrator for the IoT Virtual Lab.

Ensures the iot_vlab REST API is running and populated with target
devices before the agent event loop begins. Also runs the network
mapper so the agent has real reconnaissance data from its first turn.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import requests

from apiot.toolkit.lab_client import LabClient, LabOfflineError


# Default firmware to auto-spawn if the lab is empty
DEFAULT_TARGETS = ["zephyr_coap", "dvrf_v03"]

# Boot wait times (seconds)
ZEPHYR_BOOT_WAIT = 8
LINUX_BOOT_WAIT = 25

LAB_API_URL = "http://localhost:5000"
LAB_HEALTH_RETRIES = 15
LAB_HEALTH_INTERVAL = 2  # seconds


def _resolve_vlab_path() -> Path:
    """Locate the iot_vlab directory."""
    env_path = os.getenv("IOT_VLAB_PATH")
    if env_path:
        return Path(env_path).resolve()

    # Default: sibling directory to apiot
    apiot_root = Path(__file__).resolve().parent.parent  # apiot/
    candidates = [
        apiot_root.parent / "iot_vlab",        # ../iot_vlab (same parent)
        apiot_root / "iot_vlab",               # apiot/iot_vlab (nested)
    ]
    for candidate in candidates:
        if (candidate / "lab_api.py").exists():
            return candidate

    raise FileNotFoundError(
        "Cannot find iot_vlab directory. Set IOT_VLAB_PATH env var or "
        "place iot_vlab as a sibling directory to apiot."
    )


def _is_lab_online() -> bool:
    """Quick health check against the lab API."""
    try:
        resp = requests.get(f"{LAB_API_URL}/topology", timeout=3)
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


def _start_lab_api(vlab_path: Path) -> subprocess.Popen:
    """Launch lab_api.py as a background subprocess."""
    print("[Lab Bridge] Starting iot_vlab REST API...")
    proc = subprocess.Popen(
        [sys.executable, str(vlab_path / "lab_api.py")],
        cwd=str(vlab_path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def _wait_for_lab_healthy():
    """Poll the lab API until it responds."""
    for i in range(LAB_HEALTH_RETRIES):
        if _is_lab_online():
            print("[Lab Bridge] Lab API is healthy.")
            return
        time.sleep(LAB_HEALTH_INTERVAL)
        print(f"[Lab Bridge] Waiting for lab API... ({i + 1}/{LAB_HEALTH_RETRIES})")

    raise TimeoutError(
        f"Lab API did not become healthy after {LAB_HEALTH_RETRIES * LAB_HEALTH_INTERVAL}s. "
        "Is port 5000 blocked?"
    )


def _populate_lab(lab: LabClient):
    """Spawn default targets if the lab topology is empty."""
    topology = lab.get_topology()
    if topology:
        print(f"[Lab Bridge] Lab already has {len(topology)} device(s). Skipping spawn.")
        return

    print(f"[Lab Bridge] Lab is empty. Spawning default targets: {DEFAULT_TARGETS}")
    for fw_id in DEFAULT_TARGETS:
        try:
            result = lab.spawn_device(fw_id)
            print(f"[Lab Bridge]   Spawned {fw_id} -> {result}")
        except Exception as e:
            print(f"[Lab Bridge]   Failed to spawn {fw_id}: {e}")

    # Wait for devices to boot
    wait = max(LINUX_BOOT_WAIT if any("dvrf" in t or "debian" in t for t in DEFAULT_TARGETS) else ZEPHYR_BOOT_WAIT, ZEPHYR_BOOT_WAIT)
    print(f"[Lab Bridge] Waiting {wait}s for devices to boot...")
    time.sleep(wait)


def _run_mapper(subnet: str = "192.168.100.0/24"):
    """Run the APIOT network mapper to populate network_state.json."""
    print("[Lab Bridge] Running network mapper...")
    try:
        from apiot.core.mapper import NetworkMapper
        NetworkMapper(subnet=subnet).run()
        print("[Lab Bridge] Mapper complete. network_state.json updated.")
    except Exception as e:
        print(f"[Lab Bridge] Mapper failed (non-fatal): {e}")
        print("[Lab Bridge] The agent can still use manage_lab tools to inspect topology.")


def ensure_lab_ready(skip_bootstrap: bool = False, subnet: str = "192.168.100.0/24"):
    """Full pre-flight sequence. Call this before the agent loop.

    Args:
        skip_bootstrap: If True, skip auto-start and auto-populate.
                        Useful when the lab is already running externally.
        subnet: Target network to map after devices boot.
    """
    if skip_bootstrap:
        print("[Lab Bridge] Bootstrap skipped (--skip-bootstrap).")
        return

    print("[Lab Bridge] Running pre-flight checks...")

    lab = LabClient(base_url=LAB_API_URL)

    # Step 1: Ensure the API is running
    if not _is_lab_online():
        try:
            vlab_path = _resolve_vlab_path()
            _start_lab_api(vlab_path)
            _wait_for_lab_healthy()
        except FileNotFoundError as e:
            print(f"[Lab Bridge] {e}")
            print("[Lab Bridge] Continuing without auto-start. Agent can use manage_lab tools.")
            return
        except TimeoutError as e:
            print(f"[Lab Bridge] {e}")
            return
    else:
        print("[Lab Bridge] Lab API already running.")

    # Step 2: Populate with default targets if empty
    try:
        _populate_lab(lab)
    except Exception as e:
        print(f"[Lab Bridge] Populate failed: {e}")

    # Step 3: Run mapper with the user-specified subnet
    _run_mapper(subnet=subnet)

    print("[Lab Bridge] Pre-flight complete. Ready for agent loop.\n")
