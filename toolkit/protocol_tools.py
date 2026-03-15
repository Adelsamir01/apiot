"""protocol_tools.py — Low-level OT protocol primitives for APIOT.

These are the raw building blocks the LLM agent uses to probe and attack
IoT devices. Unlike the old named exploits, these require the agent to reason
about protocol structure and craft its own attack logic.

CoAP (RFC 7252):
  coap_send      — send any CoAP datagram by specifying header fields and options

Modbus/TCP (IETF RFC):
  modbus_request — send any Modbus PDU by specifying function code and data

Generic:
  tcp_send       — send raw bytes over TCP
  udp_send       — send raw bytes over UDP

All functions return structured dicts with sent_hex, response_hex, timing_ms
so the agent can observe exact bytes and reason about device behaviour.
"""

import socket
import struct
import time


# ── CoAP (RFC 7252) ──────────────────────────────────────────────────────────

def coap_send(ip: str, port: int = 5683,
              ver: int = 1, msg_type: int = 0, code: int = 1,
              msg_id: int = 0x1234, token_hex: str = "",
              options_hex: str = "", payload_hex: str = "",
              timeout: float = 5.0) -> dict:
    """Send a CoAP datagram and return the response.

    CoAP fixed header (4 bytes):
      Byte 0: Ver(2b) | Type(2b) | TKL(4b)
        Ver  : always 1
        Type : 0=CON, 1=NON, 2=ACK, 3=RST
        TKL  : token length in bytes (derived from token_hex)
      Byte 1: Code
        0x01=GET 0x02=POST 0x03=PUT 0x04=DELETE
        Response codes: 0x41=2.01Created 0x44=2.04Changed 0x45=2.05Content
                        0x80=4.00BadReq 0x82=4.02BadOption 0x84=4.04NotFound
      Bytes 2-3: Message ID (big-endian uint16)

    token_hex   : hex bytes for the token, e.g. "01 02" (TKL computed automatically)
    options_hex : raw option bytes (delta-length-value encoded per RFC 7252).
                  Example: "DD FF FF" injects the overflow-triggering option byte.
    payload_hex : application payload bytes (0xFF marker prepended automatically)

    Returns: {success, sent_hex, response_hex, response_len, timing_ms, details}
    """
    token_bytes = bytes.fromhex(token_hex.replace(" ", "")) if token_hex else b""
    options_bytes = bytes.fromhex(options_hex.replace(" ", "")) if options_hex else b""
    payload_bytes = bytes.fromhex(payload_hex.replace(" ", "")) if payload_hex else b""

    tkl = len(token_bytes)
    byte0 = ((ver & 0x3) << 6) | ((msg_type & 0x3) << 4) | (tkl & 0xF)
    header = struct.pack(">BBH", byte0, code & 0xFF, msg_id & 0xFFFF)
    packet = header + token_bytes + options_bytes
    if payload_bytes:
        packet += bytes([0xFF]) + payload_bytes

    t0 = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, port))
            try:
                resp, _ = s.recvfrom(4096)
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": packet.hex(),
                    "response_hex": resp.hex(),
                    "response_len": len(resp),
                    "timing_ms": elapsed,
                }
            except socket.timeout:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": packet.hex(),
                    "response_hex": "",
                    "response_len": 0,
                    "timing_ms": elapsed,
                    "details": "No CoAP response within timeout — device may have dropped or crashed",
                }
    except OSError as e:
        return {"success": False, "details": str(e), "sent_hex": packet.hex()}


# ── Modbus/TCP ────────────────────────────────────────────────────────────────

def modbus_request(ip: str, port: int = 502,
                   function_code: int = 0x03,
                   data_hex: str = "00 00 00 01",
                   unit_id: int = 1,
                   transaction_id: int = 1,
                   claimed_length: int | None = None,
                   timeout: float = 5.0) -> dict:
    """Send a Modbus/TCP request and return the response.

    MBAP Header (7 bytes):
      Transaction ID : uint16 big-endian  (echo'd back in response)
      Protocol ID    : 0x0000 (always Modbus)
      Length         : uint16 big-endian  (bytes following, including unit_id)
      Unit ID        : uint8

    PDU: function_code (1 byte) + data

    function_code: decimal value, e.g.:
      0x01 Read Coils            0x05 Write Single Coil
      0x02 Read Discrete Inputs  0x06 Write Single Register
      0x03 Read Holding Registers 0x0F Write Multiple Coils
      0x04 Read Input Registers   0x10 Write Multiple Registers

    data_hex: hex bytes for the PDU data field, e.g.:
      "00 00 00 01"  → address 0x0000, count 1  (for read operations)
      "00 00 FF 00"  → address 0x0000, value 0xFF00 (coil ON for FC 0x05)

    claimed_length: override the MBAP Length field (for overflow testing).
      Normal: len(PDU)+1. Overflow: set to e.g. 2048 (0x0800).
      If None, length is computed correctly.

    Returns: {success, sent_hex, response_hex, response_len, timing_ms,
              claimed_length, actual_pdu_length, details}
    """
    data_bytes = bytes.fromhex(data_hex.replace(" ", "")) if data_hex else b""
    pdu = bytes([function_code & 0xFF]) + data_bytes

    actual_length = len(pdu) + 1  # +1 for unit_id
    length_field = claimed_length if claimed_length is not None else actual_length

    mbap = struct.pack(">HHHB",
                       transaction_id & 0xFFFF,
                       0x0000,
                       length_field & 0xFFFF,
                       unit_id & 0xFF)
    packet = mbap + pdu

    t0 = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(packet)
            try:
                resp = s.recv(4096)
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": packet.hex(),
                    "response_hex": resp.hex(),
                    "response_len": len(resp),
                    "timing_ms": elapsed,
                    "claimed_length": length_field,
                    "actual_pdu_length": len(pdu),
                }
            except socket.timeout:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": packet.hex(),
                    "response_hex": "",
                    "response_len": 0,
                    "timing_ms": elapsed,
                    "claimed_length": length_field,
                    "actual_pdu_length": len(pdu),
                    "details": "No Modbus response within timeout — device may have crashed",
                }
    except (ConnectionRefusedError, ConnectionResetError) as e:
        return {"success": False, "details": f"Connection failed: {e}", "sent_hex": packet.hex()}
    except socket.timeout:
        return {"success": False, "details": "TCP connect timed out", "sent_hex": packet.hex()}
    except OSError as e:
        return {"success": False, "details": str(e), "sent_hex": packet.hex()}


# ── Generic raw sockets ───────────────────────────────────────────────────────

def tcp_send(ip: str, port: int, payload_hex: str,
             timeout: float = 5.0) -> dict:
    """Send raw bytes over TCP and return the response.

    payload_hex: hex string of bytes to send, e.g. "48 54 54 50" or "48545450"
    Returns: {success, sent_hex, response_hex, response_len, timing_ms, details}
    """
    payload = bytes.fromhex(payload_hex.replace(" ", ""))
    t0 = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(payload)
            try:
                resp = s.recv(4096)
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": payload.hex(),
                    "response_hex": resp.hex(),
                    "response_len": len(resp),
                    "timing_ms": elapsed,
                }
            except socket.timeout:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": payload.hex(),
                    "response_hex": "",
                    "response_len": 0,
                    "timing_ms": elapsed,
                    "details": "No response within timeout",
                }
    except (ConnectionRefusedError, ConnectionResetError) as e:
        return {"success": False, "details": f"Connection failed: {e}", "sent_hex": payload.hex()}
    except socket.timeout:
        return {"success": False, "details": "TCP connect timed out", "sent_hex": payload.hex()}
    except OSError as e:
        return {"success": False, "details": str(e), "sent_hex": payload.hex()}


def udp_send(ip: str, port: int, payload_hex: str,
             timeout: float = 5.0) -> dict:
    """Send raw bytes over UDP and return any response.

    payload_hex: hex string of bytes to send
    Returns: {success, sent_hex, response_hex, response_len, timing_ms, details}
    """
    payload = bytes.fromhex(payload_hex.replace(" ", ""))
    t0 = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            try:
                resp, _ = s.recvfrom(4096)
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": payload.hex(),
                    "response_hex": resp.hex(),
                    "response_len": len(resp),
                    "timing_ms": elapsed,
                }
            except socket.timeout:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "success": True,
                    "sent_hex": payload.hex(),
                    "response_hex": "",
                    "response_len": 0,
                    "timing_ms": elapsed,
                    "details": "No UDP response — device may have dropped or crashed",
                }
    except OSError as e:
        return {"success": False, "details": str(e), "sent_hex": payload.hex()}
