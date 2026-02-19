"""state.py — Persistent agent memory backed by a JSON file."""

import json
from pathlib import Path

DEFAULT_STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "network_state.json"


class AgentMemory:
    """Tracks discovered hosts, fingerprints, and vulnerabilities on disk."""

    def __init__(self, path: Path = DEFAULT_STATE_FILE):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._state: dict = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            return json.loads(self.path.read_text())
        return {"discovered_hosts": {}, "fingerprints": {}, "active_vulnerabilities": {}}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._state, indent=2))

    def update_host(self, ip: str, data: dict) -> None:
        """Merge data into the record for a given IP."""
        entry = self._state["discovered_hosts"].get(ip, {})
        entry.update(data)
        self._state["discovered_hosts"][ip] = entry
        self._save()

    def update_fingerprint(self, ip: str, data: dict) -> None:
        """Store or merge fingerprint data for a given IP."""
        entry = self._state["fingerprints"].get(ip, {})
        entry.update(data)
        self._state["fingerprints"][ip] = entry
        self._save()

    def add_vulnerability(self, vuln_id: str, data: dict) -> None:
        """Record a discovered vulnerability."""
        self._state["active_vulnerabilities"][vuln_id] = data
        self._save()

    def get_full_context(self) -> dict:
        """Return the entire state dictionary (for LLM context injection)."""
        return self._state

    def clear(self) -> None:
        """Reset all state."""
        self._state = {"discovered_hosts": {}, "fingerprints": {}, "active_vulnerabilities": {}}
        self._save()
