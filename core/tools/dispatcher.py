"""dispatcher.py — Routes LLM tool calls to the underlying APIOT Python functions.

Takes a tool_call name and its parsed arguments dict, executes the
matching toolkit function, and returns stringified JSON for the
conversation history.
"""

import json
import subprocess
from pathlib import Path

from apiot.core.agent_loop import (
    cmd_get_state,
    cmd_get_targets,
    cmd_stealth_check,
    cmd_attack,
    cmd_verify_crash,
    cmd_verify_shell,
    cmd_remote_exec,
    cmd_analyze_attacks,
    cmd_apply_patch,
    cmd_verify_patch,
    cmd_list_patches,
    TOOLS,
)
from apiot.core.evolve import load_dynamic_tool
from apiot.toolkit.lab_client import LabClient

_lab = LabClient()

DYNAMIC_DIR = Path(__file__).resolve().parent.parent.parent / "toolkit"

MAX_OUTPUT = 8000


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

    elif name == "remote_exec":
        return cmd_remote_exec(
            args["ip"], args["command"],
            creds=args.get("creds", "root:root"),
            timeout=args.get("timeout", 30),
        )

    elif name == "inspect_lab":
        return _dispatch_lab(args)

    elif name == "run_command":
        return _dispatch_command(args)

    elif name == "create_tool":
        return _dispatch_create_tool(args)

    elif name == "analyze_attacks":
        return cmd_analyze_attacks()

    elif name == "apply_patch":
        return cmd_apply_patch(args["signature"], dry_run=args.get("dry_run", False))

    elif name == "verify_patch":
        return cmd_verify_patch(args["attack_name"], args["target_ip"])

    elif name == "list_patches":
        return cmd_list_patches()

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


def _dispatch_command(args: dict) -> dict:
    """Execute a shell command and return structured output."""
    command = args["command"]
    timeout = min(args.get("timeout", 30), 120)

    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=True, text=True,
            timeout=timeout,
        )
        stdout = result.stdout[:MAX_OUTPUT]
        stderr = result.stderr[:MAX_OUTPUT]
        truncated = len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT
        return {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s", "command": command}
    except Exception as e:
        return {"error": str(e), "command": command}


def _dispatch_create_tool(args: dict) -> dict:
    """Write a dynamic Python tool, load it, execute it, and register it."""
    name = args["name"]
    code = args["code"]
    target_ip = args["target_ip"]
    target_port = args["target_port"]

    if not name.replace("_", "").isalnum():
        return {"error": "Tool name must be lowercase_snake_case alphanumeric."}

    filepath = DYNAMIC_DIR / f"{name}.py"
    filepath.write_text(code)

    try:
        mod = load_dynamic_tool(filepath)
    except Exception as e:
        filepath.unlink(missing_ok=True)
        return {"error": f"Failed to load tool module: {e}"}

    if not hasattr(mod, "run") or not callable(mod.run):
        filepath.unlink(missing_ok=True)
        return {"error": "Tool module must define: def run(ip: str, port: int, **kwargs) -> dict"}

    try:
        result = mod.run(target_ip, target_port)
    except Exception as e:
        return {
            "error": f"Tool executed but raised: {e}",
            "tool_path": str(filepath),
            "registered": False,
        }

    TOOLS[name] = {
        "fn": lambda ip, _mod=mod, **kw: _mod.run(ip, int(kw.get("port", target_port)), **kw),
        "category": "Dynamic",
        "description": f"Agent-created tool: {name}",
        "packets": 1,
    }

    return {
        "success": True,
        "tool_name": name,
        "tool_path": str(filepath),
        "registered": True,
        "execution_result": result,
    }
