import socket

def run(ip: str, port: int = 5683, **kwargs) -> dict:
    """Custom CoAP probe - send GET request with different options."""
    try:
        # Try different CoAP payload patterns
        payloads = [
            # Simple GET
            b'\x40\x01\x00\x00',
            # GET with Observe option
            b'\x40\x01\x00\x00\x60\x00',
            # Long URI-Path
            b'\x00\x00\xff\x41' + b'A' * 255,
        ]
        
        results = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        
        for i, payload in enumerate(payloads):
            try:
                sock.sendto(payload, (ip, port))
                data, _ = sock.recvfrom(512)
                results.append(f"Payload {i}: {data.hex()}")
            except socket.timeout:
                results.append(f"Payload {i}: timeout")
        
        sock.close()
        return {"status": "probed", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}
