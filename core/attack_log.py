"""attack_log.py — High-fidelity persistent attack logger for research benchmarking."""

import json
import time
from pathlib import Path

DEFAULT_LOG_FILE = Path(__file__).resolve().parent.parent / "data" / "attack_log.json"


class AttackLogger:
    """Append-only structured log of every attack step."""

    def __init__(self, path: Path = DEFAULT_LOG_FILE):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: list[dict] = self._load()
        self.total_packets = 0

    def _load(self) -> list[dict]:
        if self.path.exists() and self.path.stat().st_size > 0:
            return json.loads(self.path.read_text())
        return []

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._entries, indent=2))

    def log(self, target_ip: str, target_arch: str, tool_used: str,
            payload_hex: str = "", packets_sent: int = 1,
            outcome: str = "unknown", details: dict | None = None) -> dict:
        """Record one attack step. Returns the entry for chaining."""
        entry = {
            "timestamp": time.time(),
            "target_ip": target_ip,
            "target_arch": target_arch,
            "tool_used": tool_used,
            "payload_hex": payload_hex,
            "packets_sent": packets_sent,
            "outcome": outcome,
            "details": details or {},
        }
        self._entries.append(entry)
        self.total_packets += packets_sent
        self._save()
        return entry

    def get_summary(self) -> dict:
        """Return aggregate stats."""
        successes = sum(1 for e in self._entries if e["outcome"] == "success")
        failures = sum(1 for e in self._entries if e["outcome"] == "failure")
        crashes = sum(1 for e in self._entries if e["outcome"] == "crash_verified")
        return {
            "total_steps": len(self._entries),
            "total_packets": sum(e["packets_sent"] for e in self._entries),
            "successes": successes,
            "failures": failures,
            "crashes_verified": crashes,
            "packets_per_vulnerability": (
                sum(e["packets_sent"] for e in self._entries) / max(successes + crashes, 1)
            ),
        }

    def clear(self) -> None:
        self._entries = []
        self.total_packets = 0
        self._save()
