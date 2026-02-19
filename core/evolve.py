"""evolve.py — Self-evolution module for the Red Agent.

When all existing exploits for a target architecture fail, the agent
can generate a small dynamic tool, register it, and retry.
"""

import importlib.util
import textwrap
from pathlib import Path
from typing import Callable, Optional

DYNAMIC_DIR = Path(__file__).resolve().parent.parent / "toolkit"


def generate_udp_flooder(name: str = "dynamic_udp_probe") -> Path:
    """Write a lightweight UDP availability probe script.

    Returns the path to the new module so the caller can import it.
    """
    filepath = DYNAMIC_DIR / f"{name}.py"
    code = textwrap.dedent('''\
        """Auto-generated UDP availability probe."""
        import socket

        def udp_flood_probe(ip: str, port: int, count: int = 5,
                            timeout: float = 3.0) -> dict:
            """Send *count* minimal UDP datagrams and measure responses.

            Returns structured result with availability ratio.
            """
            sent = 0
            received = 0
            for _ in range(count):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(timeout)
                        s.sendto(b"\\x00", (ip, port))
                        sent += 1
                        try:
                            s.recvfrom(1024)
                            received += 1
                        except socket.timeout:
                            pass
                except OSError:
                    sent += 1
            return {
                "success": True,
                "attack": "udp_flood_probe",
                "packets_sent": sent,
                "packets_received": received,
                "availability": received / max(sent, 1),
                "port_responsive": received > 0,
            }
    ''')
    filepath.write_text(code)
    return filepath


def load_dynamic_tool(filepath: Path) -> object:
    """Import a dynamically generated module and return it."""
    spec = importlib.util.spec_from_file_location(filepath.stem, str(filepath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ToolRegistry:
    """Tracks available exploit functions (static + dynamic)."""

    def __init__(self):
        self._tools: dict[str, Callable] = {}

    def register(self, name: str, fn: Callable) -> None:
        self._tools[name] = fn

    def get(self, name: str) -> Optional[Callable]:
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())

    def has(self, name: str) -> bool:
        return name in self._tools
