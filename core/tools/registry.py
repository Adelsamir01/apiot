"""registry.py — OpenAI-compatible JSON Schema tool definitions for APIOT.

These schemas are passed directly to the OpenRouter chat completions
endpoint as the `tools` parameter. Each entry maps 1:1 to an
action the agent can invoke via native tool calling.
"""

TOOL_SCHEMAS = [
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
                "Return a filtered list of targets that have known attack surfaces, "
                "along with the list of exploit tools available. Use this as your "
                "primary reconnaissance step to decide what to attack next."
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
    {
        "type": "function",
        "function": {
            "name": "execute_exploit",
            "description": (
                "Fire a specific exploit tool against a target IP. "
                "You MUST call verify_crash or verify_shell after this to confirm results."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "enum": [
                            "modbus_write_coil",
                            "modbus_mbap_overflow",
                            "coap_option_overflow",
                            "http_cmd_injection",
                            "brute_force_telnet",
                        ],
                        "description": "The exploit tool to use.",
                    },
                    "ip": {
                        "type": "string",
                        "description": "Target IP address.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target port (optional, uses tool default if omitted).",
                    },
                    "options": {
                        "type": "object",
                        "description": (
                            "Additional key-value options for the exploit "
                            "(e.g. {\"action\": \"off\"} for modbus_write_coil, "
                            "or {\"payload\": \"id\"} for http_cmd_injection)."
                        ),
                        "additionalProperties": {"type": "string"},
                    },
                },
                "required": ["tool_name", "ip"],
            },
        },
    },
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
]
