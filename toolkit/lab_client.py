"""lab_client.py — Python client for the iot_vlab REST API."""

import requests


class LabOfflineError(ConnectionError):
    """Raised when the lab API is unreachable."""


class LabClient:
    """Structured interface to the iot_vlab REST API (default http://localhost:5000)."""

    def __init__(self, base_url: str = "http://localhost:5000", timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs) -> dict | list:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.request(method, url, timeout=self.timeout, **kwargs)
        except requests.ConnectionError:
            raise LabOfflineError(f"Lab API unreachable at {self.base_url}")
        if not resp.ok:
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            raise RuntimeError(f"API {method} {path} -> {resp.status_code}: {body.get('error', resp.text)}")
        return resp.json()

    def get_library(self) -> list[dict]:
        """Return list of available firmware configs."""
        return self._request("GET", "/library")

    def spawn_device(self, firmware_id: str) -> dict:
        """Boot a device. Returns {'run_id': '...'}."""
        return self._request("POST", "/spawn", json={"firmware_id": firmware_id})

    def get_topology(self) -> list[dict]:
        """Return list of active VM instances with IPs."""
        return self._request("GET", "/topology")

    def kill_device(self, run_id: str) -> dict:
        """Stop a specific device by run_id."""
        return self._request("POST", f"/kill/{run_id}")

    def reset_lab(self) -> dict:
        """Kill all running instances."""
        return self._request("POST", "/reset_lab")
