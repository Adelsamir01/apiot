"""dispatcher.py — Routes LLM tool calls to the underlying APIOT Python functions.

Takes a tool_call name and its parsed arguments dict, executes the
matching toolkit function, and returns stringified JSON for the
conversation history.
"""

import json
from apiot.core.agent_loop import (
    cmd_get_state,
    cmd_get_targets,
    cmd_stealth_check,
    cmd_attack,
    cmd_verify_crash,
    cmd_verify_shell,
)
from apiot.toolkit.lab_client import LabClient


_lab = LabClient()


def dispatch_tool(name: str, arguments: dict) -> str:
    """Execute a tool by name and return a JSON string result."""
    try:
        result = _dispatch(name, arguments)
    except Exception as e:
        result = {"error": str(e), "tool": name}

    return json.dumps(result, indent=2, default=str)


def _dispatch(name: str, args: dict) -> dict | list:
    """Internal routing logic."""

    if name == "get_network_state":
        return cmd_get_state()

    elif name == "get_actionable_targets":
        return cmd_get_targets()

    elif name == "stealth_check":
        return cmd_stealth_check(args["ip"])

    elif name == "execute_exploit":
        kwargs = {}
        if "port" in args:
            kwargs["port"] = str(args["port"])
        if "options" in args and isinstance(args["options"], dict):
            kwargs.update(args["options"])
        return cmd_attack(args["tool_name"], args["ip"], **kwargs)

    elif name == "verify_crash":
        return cmd_verify_crash(args["ip"])

    elif name == "verify_shell":
        port = args.get("port", 23)
        return cmd_verify_shell(args["ip"], port)

    elif name == "inspect_lab":
        return _dispatch_lab(args)

    else:
        return {"error": f"Unknown tool: {name}"}


def _dispatch_lab(args: dict) -> dict | list:
    """Handle read-only lab queries."""
    action = args["action"]

    if action == "topology":
        return _lab.get_topology()

    elif action == "library":
        return _lab.get_library()

    else:
        return {"error": f"Unknown lab action: {action}"}
