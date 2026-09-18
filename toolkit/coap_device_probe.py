import socket
import struct

def run(ip: str, port: int = 5683, **kwargs) -> dict:
    """Send CoAP GET request to probe device information."""
    try:
        # CoAP message: Ver=1, Type=0 (Confirmable), Code=1 (GET), Token=0x01
        # URI-Path: "devinfo" 
        msg = bytes([
            0x40, 0x01, 0x00, 0x01,  # Header
            0x01,                     # Token length=1
            0x01,                     # Token
            0x00, 0x0b,              # Uri-Path option (delta=0, len=11)
        ]) + b"device-info"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(msg, (ip, port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        
        return {"status": "success", "response": data.hex(), "info": "CoAP device info probe sent"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
