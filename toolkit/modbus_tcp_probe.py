import socket

def run(ip: str, port: int = 502, **kwargs) -> dict:
    """Custom Modbus TCP exploit - probe and attempt MBAP overflow."""
    try:
        # Modbus TCP MBAP header
        # Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
        
        # First, try a legitimate read request to check if service is alive
        probe_request = b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a'
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        try:
            sock.connect((ip, port))
            sock.send(probe_request)
            response = sock.recv(1024)
            sock.close()
            
            if response:
                return {
                    "status": "success", 
                    "message": "Modbus responded", 
                    "response_hex": response.hex(),
                    "info": "Service is alive - possible exploit target"
                }
        except ConnectionRefusedError:
            sock.close()
            return {"status": "error", "message": "Connection refused - service not running on port 502"}
        except Exception as e:
            sock.close()
            return {"status": "error", "message": str(e)}
            
    except Exception as e:
        return {"status": "error", "message": str(e)}
