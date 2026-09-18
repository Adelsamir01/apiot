"""analyzer.py — Payload Analyzer for the Blue Agent.

Deconstructs Red Agent exploit payloads into defensive signatures
that can be used to generate virtual patches (iptables rules).
"""

import struct
from apiot.core.attack_log import AttackLogger


# Known attack tool → analysis strategy
ANALYZERS = {
    "coap_option_overflow": "_analyze_coap_overflow",
    "modbus_mbap_overflow": "_analyze_modbus_overflow",
    "modbus_write_coil": "_analyze_modbus_write",
    "http_cmd_injection": "_analyze_http_injection",
}


class PayloadAnalyzer:

    def analyze_attack_log(self) -> list[dict]:
        """Scan attack_log.json for confirmed exploits and return signatures."""
        logger = AttackLogger()
        entries = logger._entries
        signatures = []
        for entry in entries:
            if entry["outcome"] not in ("crash_verified", "delivered", "success"):
                continue
            tool = entry.get("tool_used", "")
            method_name = ANALYZERS.get(tool)
            if method_name is None:
                continue
            sig = getattr(self, method_name)(entry)
            if sig:
                signatures.append(sig)
        return signatures

    def analyze_single(self, entry: dict) -> dict | None:
        """Analyze one attack log entry."""
        tool = entry.get("tool_used", "")
        method_name = ANALYZERS.get(tool)
        if method_name is None:
            return None
        return getattr(self, method_name)(entry)

    def _analyze_coap_overflow(self, entry: dict) -> dict:
        """CoAP option overflow: packet contains 0xDD option byte (delta=13, len=13).

        Signature: match the 0xDD option byte in the CoAP options section.
        iptables --hex-string "|DD|" is correct: the length module checks total
        IP packet length (not UDP payload), so string matching on the exploit
        byte is the reliable approach.
        """
        payload_hex = entry.get("payload_hex", "")
        payload_len = len(bytes.fromhex(payload_hex)) if payload_hex else 0
        return {
            "attack": "coap_option_overflow",
            "target_ip": entry.get("target_ip"),
            "protocol": "udp",
            "port": 5683,
            "signature_type": "hex_string",
            "description": f"Malformed CoAP: {payload_len}-byte datagram with 0xDD overflow option byte",
            "filter": {
                "direction": "FORWARD",
                "protocol": "udp",
                "dport": 5683,
                "match": "hex_string",
                "hex_pattern": "DD",
                "algo": "bm",
                "action": "DROP",
            },
        }

    def _analyze_modbus_overflow(self, entry: dict) -> dict:
        """Modbus MBAP overflow: length field claims 2048 (0x0800).

        Signature: match the 0x08 0x00 bytes in the MBAP length field.
        Normal Modbus requests have MBAP length < 256 (fits in one byte),
        so matching |08 00| (2048) is a reliable overflow indicator.
        """
        payload_hex = entry.get("payload_hex", "")
        payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""
        claimed_len = 0
        if len(payload_bytes) >= 6:
            claimed_len = struct.unpack(">H", payload_bytes[4:6])[0]
        # Extract the hex pattern from the actual exploit payload's length field
        if len(payload_bytes) >= 6:
            hex_pattern = payload_bytes[4:6].hex().upper()
            hex_pattern = " ".join(hex_pattern[i:i+2] for i in range(0, len(hex_pattern), 2))
        else:
            hex_pattern = "08 00"  # default: 2048 in big-endian
        return {
            "attack": "modbus_mbap_overflow",
            "target_ip": entry.get("target_ip"),
            "protocol": "tcp",
            "port": 502,
            "signature_type": "hex_string",
            "description": f"MBAP length field = {claimed_len} (0x{claimed_len:04X}) — overflow indicator",
            "filter": {
                "direction": "FORWARD",
                "protocol": "tcp",
                "dport": 502,
                "match": "hex_string",
                "hex_pattern": hex_pattern,
                "algo": "bm",
                "action": "DROP",
            },
        }

    def _analyze_modbus_write(self, entry: dict) -> dict:
        """Modbus write coil: FC 0x05 to alter physical state.

        Signature: block Modbus FC 0x05 (Write Single Coil) from
        unauthorized sources. Uses hex string match on byte offset 7 = 0x05.
        """
        return {
            "attack": "modbus_write_coil",
            "target_ip": entry.get("target_ip"),
            "protocol": "tcp",
            "port": 502,
            "signature_type": "content",
            "description": "Modbus FC 0x05 (Write Single Coil) — unauthorized state change",
            "filter": {
                "direction": "FORWARD",
                "protocol": "tcp",
                "dport": 502,
                "match": "u32",
                "u32_expr": "0>>22&0x3C@7&0xFF=0x05",
                "action": "DROP",
            },
        }

    def _analyze_http_injection(self, entry: dict) -> dict:
        """HTTP command injection: shell metacharacters in params."""
        return {
            "attack": "http_cmd_injection",
            "target_ip": entry.get("target_ip"),
            "protocol": "tcp",
            "port": 80,
            "signature_type": "string",
            "description": "Shell metacharacter injection via HTTP parameter",
            "filter": {
                "direction": "FORWARD",
                "protocol": "tcp",
                "dport": 80,
                "match": "string",
                "pattern": "/bin/sh",
                "algo": "bm",
                "action": "DROP",
            },
        }
