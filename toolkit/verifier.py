"""verifier.py — Post-exploit verification engine.

Provides objective proof that an exploit succeeded, preventing the
LLM agent from hallucinating success.
"""

import socket
import struct
import subprocess
import time

UDP_PORTS = {5683}


def verify_crash(ip: str, known_ports: list[int] | None = None,
                 timeout: float = 10.0) -> dict:
    """Verify a target has crashed by checking ICMP ping + service probes.

    Uses TCP handshake for TCP ports and a lightweight CoAP ping for
    UDP-only ports (e.g. 5683). If the host fails to respond on all
    channels within *timeout* seconds, it is considered crashed.
    """
    if known_ports is None:
        known_ports = [502, 4242, 5683, 22, 80]

    ping_ok = _ping(ip, timeout=timeout)
    if not ping_ok:
        return {"status": "crashed", "verified": True, "ip": ip,
                "details": "ICMP ping failed"}

    for port in known_ports:
        if port in UDP_PORTS:
            if _udp_coap_ping(ip, port, timeout=min(timeout, 5.0)):
                return {"status": "alive", "verified": False, "ip": ip,
                        "details": f"UDP CoAP probe got response on port {port}"}
        else:
            if _tcp_handshake(ip, port, timeout=min(timeout, 5.0)):
                return {"status": "alive", "verified": False, "ip": ip,
                        "details": f"TCP handshake succeeded on port {port}"}

    return {"status": "crashed", "verified": True, "ip": ip,
            "details": f"Ping OK but all probed ports {known_ports} unresponsive"}


def verify_shell(ip: str, port: int = 23, trigger_cmd: str = "echo APIOT_PWNED",
                 marker: str = "APIOT_PWNED", timeout: float = 10.0) -> dict:
    """Verify shell access by sending a command and checking for the marker."""
    return _verify_via_tcp(ip, port, trigger_cmd, marker, timeout)


def _ping(ip: str, timeout: float = 5.0) -> bool:
    count_s = max(1, int(timeout / 2))
    result = subprocess.run(
        ["ping", "-c", "2", "-W", str(count_s), ip],
        capture_output=True, timeout=timeout + 5,
    )
    return result.returncode == 0


def _udp_coap_ping(ip: str, port: int, timeout: float = 5.0) -> bool:
    """Send a valid CoAP Empty Confirmable message and check for any reply."""
    coap_ping = struct.pack(">BBH", 0x40, 0x00, 0xBEEF)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(coap_ping, (ip, port))
            s.recvfrom(256)
            return True
    except (socket.timeout, OSError):
        return False


def _tcp_handshake(ip: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _verify_via_tcp(ip: str, port: int, cmd: str, marker: str,
                    timeout: float) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(cmd.encode() + b"\n")
            data = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if marker.encode() in data:
                        break
                except socket.timeout:
                    break
        found = marker.encode() in data
        return {
            "status": "shell_verified" if found else "shell_unverified",
            "verified": found,
            "ip": ip,
            "port": port,
            "response_snippet": data.decode(errors="replace")[:512],
        }
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        return {"status": "connection_failed", "verified": False,
                "ip": ip, "port": port, "details": str(e)}
