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
                s.sendto(b"\x00", (ip, port))
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
