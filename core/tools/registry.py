"""registry.py — OpenAI-compatible JSON Schema tool definitions for APIOT.

These schemas are passed directly to the OpenRouter chat completions
endpoint as the `tools` parameter. Each entry maps 1:1 to an
action the agent can invoke via native tool calling.

EXT7: Replaced execute_exploit (6 named exploits), analyze_attacks, and
apply_patch with 8 protocol primitive tools that require the agent to reason
about protocol structure rather than picking from a fixed menu.
"""

TOOL_SCHEMAS = [
    # ── Reconnaissance ───────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "get_network_state",
            "description": (
                "Return the full network state including discovered hosts, "
                "fingerprints, classifications, and active vulnerabilities. "
                "Use this to understand the current situation before acting."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_actionable_targets",
            "description": (
                "Return a filtered list of targets that have known attack surfaces. "
                "Use this as your primary reconnaissance step to decide what to probe next."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stealth_check",
            "description": (
                "Measure packet loss to a target IP via ping sweep. Returns a "
                "recommendation: 'proceed', 'throttle', or 'skip'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP address (e.g. '192.168.100.35').",
                    },
                },
                "required": ["ip"],
            },
        },
    },
    # ── Red Team — Protocol Primitives ────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "coap_send",
            "description": (
                "Send a CoAP datagram (RFC 7252) and return the response. "
                "Use this to probe CoAP devices and to craft exploit payloads. "
                "Start with a normal GET to fingerprint the device, then explore "
                "malformed options (options_hex) to find parser vulnerabilities. "
                "CoAP runs over UDP (default port 5683). "
                "ALWAYS follow with verify_crash to check for device crash."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP address.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target UDP port (default: 5683).",
                    },
                    "ver": {
                        "type": "integer",
                        "description": "CoAP version (default: 1). Use 1 for valid packets.",
                    },
                    "msg_type": {
                        "type": "integer",
                        "description": "Message type: 0=CON, 1=NON, 2=ACK, 3=RST (default: 0=CON).",
                    },
                    "code": {
                        "type": "integer",
                        "description": (
                            "CoAP code: 0x01=GET 0x02=POST 0x03=PUT 0x04=DELETE "
                            "(default: 0x01=GET)."
                        ),
                    },
                    "msg_id": {
                        "type": "integer",
                        "description": "Message ID (uint16, default: 0x1234).",
                    },
                    "token_hex": {
                        "type": "string",
                        "description": "Token bytes as hex string, e.g. '01 02' (optional).",
                    },
                    "options_hex": {
                        "type": "string",
                        "description": (
                            "Raw option bytes (delta-length-value per RFC 7252), as hex. "
                            "Example: 'DD FF FF' injects option byte 0xDD (delta=13, length=13) "
                            "followed by extended bytes — triggers CoAP parser overflow."
                        ),
                    },
                    "payload_hex": {
                        "type": "string",
                        "description": "Application payload bytes as hex (0xFF marker prepended automatically).",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Response timeout in seconds (default: 5.0).",
                    },
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "modbus_request",
            "description": (
                "Send a Modbus/TCP request and return the response. "
                "Use this to probe Modbus devices and to craft exploit payloads. "
                "Start with a normal FC 0x03 Read Holding Registers to fingerprint the "
                "device, then explore protocol edge cases (e.g. oversized claimed_length "
                "in the MBAP header) to find vulnerabilities. "
                "Modbus runs over TCP (default port 502). "
                "ALWAYS follow with verify_crash to check for device crash."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP address.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target TCP port (default: 502).",
                    },
                    "function_code": {
                        "type": "integer",
                        "description": (
                            "Modbus Function Code (decimal): "
                            "1=ReadCoils 2=ReadDiscreteInputs 3=ReadHoldingRegisters "
                            "4=ReadInputRegisters 5=WriteSingleCoil 6=WriteSingleRegister "
                            "(default: 3)."
                        ),
                    },
                    "data_hex": {
                        "type": "string",
                        "description": (
                            "PDU data bytes as hex string. "
                            "For read ops: '00 00 00 01' (address 0, count 1). "
                            "For FC 0x05 WriteSingleCoil: '00 00 FF 00' (addr 0, ON)."
                        ),
                    },
                    "unit_id": {
                        "type": "integer",
                        "description": "Modbus unit/slave ID (default: 1).",
                    },
                    "transaction_id": {
                        "type": "integer",
                        "description": "MBAP transaction ID (default: 1, echoed in response).",
                    },
                    "claimed_length": {
                        "type": "integer",
                        "description": (
                            "Override the MBAP Length field (for overflow testing). "
                            "Normal value = len(PDU)+1. Overflow example: 2048 (0x0800). "
                            "Omit for correct length."
                        ),
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Response timeout in seconds (default: 5.0).",
                    },
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tcp_send",
            "description": (
                "Send raw bytes over TCP and return the response. "
                "Use for probing TCP services when the protocol-specific tools "
                "do not apply, or for custom exploit payloads."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP address.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target TCP port.",
                    },
                    "payload_hex": {
                        "type": "string",
                        "description": "Bytes to send as hex string, e.g. '48 54 54 50 2F 31 2E 31'.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Response timeout in seconds (default: 5.0).",
                    },
                },
                "required": ["ip", "port", "payload_hex"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "udp_send",
            "description": (
                "Send raw bytes over UDP and return any response. "
                "Use for probing UDP services or for custom exploit payloads "
                "when coap_send does not apply."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP address.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target UDP port.",
                    },
                    "payload_hex": {
                        "type": "string",
                        "description": "Bytes to send as hex string.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Response timeout in seconds (default: 5.0).",
                    },
                },
                "required": ["ip", "port", "payload_hex"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mqtt_publish",
            "description": (
                "Connect to an MQTT broker (TCP port 1883), publish one message, and disconnect. "
                "Use to: (1) test broker reachability; (2) discover command-injection "
                "vulnerabilities — try publishing to 'iot/commands/shutdown' with payload "
                "'{\"action\":\"shutdown\"}' to test whether sensor devices trust unauthenticated "
                "MQTT commands; (3) verify blue-team ACL fixes by replaying the attack. "
                "MQTT uses anonymous access by default (no credentials). "
                "After publishing a shutdown command, use mqtt_subscribe to verify the "
                "sensor stopped publishing (device crashed). "
                "ALWAYS follow with mqtt_subscribe to observe the effect."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "broker_ip": {
                        "type": "string",
                        "description": "Broker IP address (e.g. '192.168.100.10').",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Broker TCP port (default: 1883).",
                    },
                    "topic": {
                        "type": "string",
                        "description": (
                            "MQTT topic to publish to. "
                            "Examples: 'iot/test', 'iot/commands/shutdown', 'iot/commands/reboot'."
                        ),
                    },
                    "payload": {
                        "type": "string",
                        "description": (
                            "Message payload as a string. "
                            "For crash trigger: '{\"action\":\"shutdown\"}' "
                            "(sends a shutdown command to any subscribed IoT device)."
                        ),
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Connection timeout in seconds (default: 10.0).",
                    },
                },
                "required": ["broker_ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mqtt_subscribe",
            "description": (
                "Connect to an MQTT broker, subscribe to a topic, and collect messages "
                "for a specified duration. "
                "Use to: (1) discover active topics — use topic='#' to see all traffic; "
                "(2) intercept sensor telemetry to understand the MQTT topic structure "
                "before crafting targeted commands; "
                "(3) verify a device has been taken down — if messages_received==0 on "
                "'iot/sensors/#' after publishing a crash command, the attack succeeded; "
                "(4) confirm a blue-team ACL fix blocked unauthorised publishes. "
                "Always start by subscribing to '#' to map the full topic tree."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "broker_ip": {
                        "type": "string",
                        "description": "Broker IP address.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Broker TCP port (default: 1883).",
                    },
                    "topic": {
                        "type": "string",
                        "description": (
                            "MQTT topic filter to subscribe to. "
                            "'#' subscribes to ALL topics (wildcard). "
                            "'iot/sensors/#' subscribes to all sensor topics. "
                            "'iot/commands/#' subscribes to all command topics."
                        ),
                    },
                    "duration": {
                        "type": "number",
                        "description": "How long to listen for messages in seconds (default: 5.0).",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Total timeout including connection (default: 15.0).",
                    },
                },
                "required": ["broker_ip"],
            },
        },
    },
    # ── Verification ─────────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "verify_crash",
            "description": (
                "Check whether a target has crashed after an attack. "
                "Probes known ports and determines if the device went offline. "
                "Automatically logs a vulnerability if verified."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP to check.",
                    },
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_shell",
            "description": (
                "Check if shell access was obtained on a target after exploitation. "
                "Automatically logs a vulnerability if verified."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP to check.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port to check for shell access (default: 23).",
                    },
                },
                "required": ["ip"],
            },
        },
    },
    # ── Lab / Host Utilities ─────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "inspect_lab",
            "description": (
                "Query the IoT Virtual Lab for read-only information. "
                "View the current device topology or list the firmware library."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["topology", "library"],
                        "description": "The read-only lab query to perform.",
                    },
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": (
                "Execute a shell command on the APIOT host machine. "
                "Use for recon (nmap, curl, netcat, ping), probing services, "
                "or any action the built-in tools cannot cover. "
                "Commands MUST only target lab subnets (192.168.100.0/24 and 192.168.200.0/24). "
                "Do NOT modify host configuration or access the internet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute (e.g. 'nmap -sV 192.168.100.10').",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait (default 30, max 120).",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_tool",
            "description": (
                "Create a new Python exploit tool at runtime. Write the code, "
                "and it will be saved, loaded, and executed immediately. "
                "The code MUST define: def run(ip: str, port: int, **kwargs) -> dict. "
                "Use this when the protocol primitives cannot express the needed attack."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Tool identifier (lowercase_snake_case, e.g. 'custom_coap_fuzz').",
                    },
                    "code": {
                        "type": "string",
                        "description": (
                            "Python source code. Must define: "
                            "def run(ip: str, port: int, **kwargs) -> dict"
                        ),
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "IP to immediately test the new tool against.",
                    },
                    "target_port": {
                        "type": "integer",
                        "description": "Port to immediately test the new tool against.",
                    },
                },
                "required": ["name", "code", "target_ip", "target_port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remote_exec",
            "description": (
                "Execute a command on a compromised target via SSH. "
                "Use after obtaining credentials via brute force. "
                "For post-exploitation: system enumeration, credential harvesting, "
                "lateral movement, service discovery on compromised hosts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Target IP with known SSH credentials.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute on the target.",
                    },
                    "creds": {
                        "type": "string",
                        "description": "Credentials as 'user:password' (default: root:root).",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait (default 30).",
                    },
                },
                "required": ["ip", "command"],
            },
        },
    },
    # ── Blue Team — Defensive Primitives ─────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "iptables_rule",
            "description": (
                "Add or remove one iptables rule on the host to protect lab devices. "
                "Applied to both FORWARD (QEMU via TAP) and INPUT (software simulators) chains. "
                "Use this to craft precise virtual patches based on what you observed in the attack. "
                "Example: block the 0xDD option byte that crashed the CoAP device "
                "(match_type='hex_string', match_value='DD', protocol='udp', dport=5683). "
                "ALWAYS follow with verify_patch to confirm the patch blocks the attack."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "chain": {
                        "type": "string",
                        "description": "Primary iptables chain: 'FORWARD' or 'INPUT' (default: 'FORWARD').",
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol to match: 'tcp' or 'udp'.",
                    },
                    "dport": {
                        "type": "integer",
                        "description": "Destination port to match (e.g. 5683, 502).",
                    },
                    "match_type": {
                        "type": "string",
                        "enum": ["plain", "hex_string", "string", "u32"],
                        "description": (
                            "Match module: "
                            "'plain' — protocol+port only (no payload match); "
                            "'hex_string' — match raw hex bytes in payload (e.g. exploit signature); "
                            "'string' — match ASCII string in payload; "
                            "'u32' — u32 expression for bit-level matching."
                        ),
                    },
                    "match_value": {
                        "type": "string",
                        "description": (
                            "The pattern for the match module. "
                            "hex_string: e.g. 'DD' or '08 00'; "
                            "string: e.g. '/bin/sh'; "
                            "u32: e.g. '0>>22&0x3C@7&0xFF=0x05'."
                        ),
                    },
                    "algo": {
                        "type": "string",
                        "description": "Matching algorithm for string/hex_string: 'bm' (default) or 'kmp'.",
                    },
                    "verdict": {
                        "type": "string",
                        "description": "Packet verdict: 'DROP' (default), 'ACCEPT', or 'LOG'.",
                    },
                    "op": {
                        "type": "string",
                        "description": "Operation: 'add' (append rule, default) or 'remove' (delete rule).",
                    },
                },
                "required": ["protocol", "dport"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "protocol_block",
            "description": (
                "Block all traffic to a specific port with a blanket DROP rule. "
                "Less precise than iptables_rule but useful when blocking an entire "
                "protocol port is acceptable (e.g. completely block Modbus port 502 "
                "from external subnets after confirming all legitimate traffic is whitelisted)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "protocol": {
                        "type": "string",
                        "description": "Protocol: 'tcp' or 'udp'.",
                    },
                    "dport": {
                        "type": "integer",
                        "description": "Destination port to block.",
                    },
                    "direction": {
                        "type": "string",
                        "description": "Chain direction: 'forward', 'input', or 'both' (default: 'both').",
                    },
                },
                "required": ["protocol", "dport"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "modbus_fc_filter",
            "description": (
                "Drop Modbus packets containing a specific Function Code. "
                "Uses u32 match on TCP payload byte 7 (Modbus PDU FC field). "
                "More surgical than protocol_block — blocks only the dangerous FC "
                "while allowing legitimate Modbus reads. "
                "Example: filter FC 5 (Write Single Coil) to prevent unauthorised "
                "physical state changes while keeping reads working."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_code": {
                        "type": "integer",
                        "description": (
                            "Modbus FC to block (decimal): "
                            "1=ReadCoils 5=WriteSingleCoil 6=WriteRegister "
                            "15=WriteMultipleCoils 16=WriteMultipleRegisters."
                        ),
                    },
                    "dport": {
                        "type": "integer",
                        "description": "Modbus TCP port (default: 502).",
                    },
                    "chain": {
                        "type": "string",
                        "description": "Primary chain: 'FORWARD' (default) or 'INPUT'.",
                    },
                },
                "required": ["function_code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "coap_rate_limit",
            "description": (
                "Rate-limit CoAP UDP traffic using iptables hashlimit. "
                "Unlike a blanket DROP, this allows legitimate CoAP traffic while "
                "absorbing burst-based attacks. Tracks per-source-IP rate."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "dport": {
                        "type": "integer",
                        "description": "CoAP UDP port (default: 5683).",
                    },
                    "rate": {
                        "type": "string",
                        "description": "iptables rate string, e.g. '10/sec', '100/min' (default: '10/sec').",
                    },
                    "burst": {
                        "type": "integer",
                        "description": "Max burst packet count before dropping begins (default: 20).",
                    },
                    "chain": {
                        "type": "string",
                        "description": "Primary chain: 'FORWARD' (default) or 'INPUT'.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_patch",
            "description": (
                "Blue Team: Replay the exact payload that previously crashed a target "
                "to confirm the patch blocks it (target SURVIVES). "
                "Wait for the device to reboot (~10 seconds for watchdog reset) before "
                "calling this. If the device survives the replay, the patch is VERIFIED_SECURE. "
                "Pass the same hex payload you used to trigger the original crash."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "IP of the target to verify the patch against.",
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol used by the attack: 'udp' (CoAP) or 'tcp' (Modbus).",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port used by the attack (e.g. 5683, 502).",
                    },
                    "payload_hex": {
                        "type": "string",
                        "description": "The exact hex payload that triggered the original crash.",
                    },
                },
                "required": ["target_ip", "protocol", "port", "payload_hex"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_patches",
            "description": (
                "Blue Team: List all current iptables FORWARD chain rules. "
                "Use to verify which patches are currently active."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
]
