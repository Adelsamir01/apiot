import socket

def run(ip: str, port: int, **kwargs) -> dict:
    """
    Fuzzing exploit for CoAP service - tests various malformed packets
    """
    results = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    # Test 1: Empty packet
    tests = [
        (b'', "empty"),
        (b'\x40\x01\x00\x00', "short_header"),
        (b'\x40\x01\x00\x00\x00\xFF\x00', "payload_no_option"),
        (b'\x40\x01\x00\x00\x00\xE0\xFF', "option_overflow"),
    ]
    
    for payload, name in tests:
        try:
            sock.sendto(payload, (ip, port))
            results.append(f"{name}: sent")
        except Exception as e:
            results.append(f"{name}: {e}")
    
    return {"success": True, "tests": results, "port": port}