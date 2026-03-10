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
                            "brute_force_ssh",
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
                "The tool is then registered so you can reuse it via execute_exploit. "
                "Use this when existing tools fail and you need a custom exploit."
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
                "Use after obtaining credentials via brute_force_ssh. "
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
    # ── Blue Team Tools ──────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "analyze_attacks",
            "description": (
                "Blue Team: Analyze the attack log and extract defensive signatures. "
                "Returns a list of signatures with filter rules that can be applied as patches. "
                "Call this after red team exploitation to begin the blue team phase."
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
            "name": "apply_patch",
            "description": (
                "Blue Team: Generate and apply an iptables virtual patch from a signature. "
                "Pass the full signature object returned by analyze_attacks. "
                "The patch is applied on the host FORWARD chain to protect lab devices."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "object",
                        "description": "The full signature dict from analyze_attacks.",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, generate the rule but don't apply it (default false).",
                    },
                },
                "required": ["signature"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_patch",
            "description": (
                "Blue Team: Replay the original attack against a patched target and confirm "
                "the device SURVIVES (patch blocks the attack). If verified, marks the "
                "vulnerability as VERIFIED_SECURE in network state."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_name": {
                        "type": "string",
                        "description": "The attack tool name to replay (e.g. 'coap_option_overflow').",
                    },
                    "target_ip": {
                        "type": "string",
                        "description": "IP of the target to verify the patch against.",
                    },
                },
                "required": ["attack_name", "target_ip"],
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
