#!/usr/bin/env python3
"""test_guardrails.py — Verify APIOT refuses to run without prerequisites.

Checks:
  1. Missing API key -> SystemExit
  2. config.require_openrouter_api_key enforces non-empty key
  3. System prompt contains TASK_ABORTED instruction
  4. System prompt contains isolation rules
  5. Agent event loop handles TASK_ABORTED as a terminal token
  6. lab_bridge aborts on unreachable lab (mocked)
  7. lab_bridge aborts on empty topology (mocked)
  8. CLI has model fetching capability
  9. CLI has lab-running confirmation prompt
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
APIOT_ROOT = PROJECT_ROOT / "apiot"
sys.path.insert(0, str(PROJECT_ROOT))

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


def test_missing_api_key_aborts():
    print("\n--- config: missing API key raises SystemExit ---")
    with patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}, clear=False):
        try:
            from importlib import reload
            import apiot.core.config as cfg
            reload(cfg)
            cfg.require_openrouter_api_key()
            check("Missing key raises SystemExit", False, "no exception raised")
        except SystemExit as e:
            check("Missing key raises SystemExit", True)
            check("Error message mentions API key", "OPENROUTER_API_KEY" in str(e))
        except Exception as e:
            check("Missing key raises SystemExit", False, f"got {type(e).__name__}: {e}")


def test_valid_api_key_passes():
    print("\n--- config: valid API key passes ---")
    with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-v1-test"}, clear=False):
        try:
            from importlib import reload
            import apiot.core.config as cfg
            reload(cfg)
            key = cfg.require_openrouter_api_key()
            check("Valid key returns string", isinstance(key, str) and len(key) > 0)
        except Exception as e:
            check("Valid key returns string", False, str(e))


def test_system_prompt_content():
    print("\n--- agent.py: system prompt contains required directives ---")
    from apiot.core.agent import SYSTEM_PROMPT

    check("Prompt mentions TASK_ABORTED", "TASK_ABORTED" in SYSTEM_PROMPT)
    check("Prompt mentions TASK_COMPLETE", "TASK_COMPLETE" in SYSTEM_PROMPT)
    check("Prompt forbids spawn/kill/reset",
          "MUST NOT" in SYSTEM_PROMPT and "spawn" in SYSTEM_PROMPT)
    check("Prompt mentions isolation model", "Isolation model" in SYSTEM_PROMPT)
    check("Prompt mentions read-only lab access", "read-only" in SYSTEM_PROMPT.lower())
    check("Prompt enforces tool-only observations",
          "never fabricate" in SYSTEM_PROMPT.lower())
    check("Prompt requires verify after exploit",
          "verify_crash" in SYSTEM_PROMPT and "verify_shell" in SYSTEM_PROMPT)


def test_terminal_tokens_handled():
    print("\n--- agent.py: TASK_ABORTED is a terminal token ---")
    from apiot.core.agent import TERMINAL_TOKENS

    check("TASK_COMPLETE is terminal", "TASK_COMPLETE" in TERMINAL_TOKENS)
    check("TASK_ABORTED is terminal", "TASK_ABORTED" in TERMINAL_TOKENS)


def test_lab_bridge_aborts_offline():
    print("\n--- lab_bridge: aborts when lab is offline ---")
    with patch("apiot.core.lab_bridge._is_lab_online", return_value=False):
        with patch("apiot.core.lab_bridge.LAB_HEALTH_RETRIES", 0):
            try:
                from apiot.core.lab_bridge import ensure_lab_ready
                ensure_lab_ready()
                check("Offline lab raises SystemExit", False, "no exception")
            except SystemExit:
                check("Offline lab raises SystemExit", True)
            except Exception as e:
                check("Offline lab raises SystemExit", False, f"got {type(e).__name__}")


def test_lab_bridge_aborts_empty_topology():
    print("\n--- lab_bridge: aborts when lab has no devices ---")
    with patch("apiot.core.lab_bridge._is_lab_online", return_value=True):
        mock_client = type("MockClient", (), {
            "get_topology": lambda self: [],
        })()
        with patch("apiot.core.lab_bridge.LabClient", return_value=mock_client):
            try:
                from apiot.core.lab_bridge import ensure_lab_ready
                ensure_lab_ready()
                check("Empty topology raises SystemExit", False, "no exception")
            except SystemExit:
                check("Empty topology raises SystemExit", True)
            except Exception as e:
                check("Empty topology raises SystemExit", False, f"got {type(e).__name__}")


def test_cli_mission_control():
    print("\n--- cli.py: Mission Control structure ---")
    from apiot.core.cli import MISSIONS, _display_network_history, _select_mission, _save_env

    check("MISSIONS has 5 modes", len(MISSIONS) == 5)
    check("_display_network_history callable", callable(_display_network_history))
    check("_select_mission callable", callable(_select_mission))
    check("_save_env callable", callable(_save_env))
    modes = [v[0] for v in MISSIONS.values()]
    check("full_purple mode exists", "full_purple" in modes)
    check("novel mode exists", "novel" in modes)


def test_cli_saves_env():
    print("\n--- cli.py: _save_env persists key/value to .env ---")
    from apiot.core.cli import _save_env, _ENV_PATH

    original = _ENV_PATH.read_text() if _ENV_PATH.exists() else ""
    try:
        _save_env("_TEST_SAVE", "hello")
        content = _ENV_PATH.read_text()
        check("Saved key present in .env", '_TEST_SAVE="hello"' in content)
        check("Original keys preserved", "OPENROUTER_API_KEY" in content)

        _save_env("_TEST_SAVE", "updated")
        content2 = _ENV_PATH.read_text()
        check("Key updated without duplication", content2.count("_TEST_SAVE") == 1)
        check("Updated value correct", '_TEST_SAVE="updated"' in content2)
    finally:
        _ENV_PATH.write_text(original)


def test_cli_uses_correct_vlab_endpoint():
    print("\n--- cli.py: uses /api/ready for readiness check ---")
    import inspect
    from apiot.core import cli
    src = inspect.getsource(cli.run)
    check("CLI checks /api/ready endpoint", "/api/ready" in src)
    check("CLI does NOT use /api/network", "/api/network" not in src)


def test_session_logging():
    print("\n--- tui.py: session logger writes to file ---")
    from apiot.core.tui import OperatorConsole

    c = OperatorConsole()
    c.start()
    c.log_system("boot")
    c.log_reasoning("thinking about targets")
    c.log_tool_call("get_actionable_targets", {"subnet": "192.168.100.0/24"})
    c.log_tool_result('{"targets": []}')
    c.log_error("something bad")
    c.stop()

    log_text = c.log_path.read_text()
    check("Log file created", c.log_path.exists())
    check("Log contains system msg", "[APIOT] boot" in log_text)
    check("Log contains reasoning", "thinking about targets" in log_text)
    check("Log contains tool call", "get_actionable_targets" in log_text)
    check("Log contains tool result (full)", '{"targets": []}' in log_text)
    check("Log contains error", "[ERROR] something bad" in log_text)
    check("Log has session markers", "Session started" in log_text and "Session ended" in log_text)

    c.log_path.unlink(missing_ok=True)


def test_no_tui_split_panel():
    print("\n--- tui.py: no split-panel TUI remnants ---")
    import inspect
    from apiot.core import tui
    src = inspect.getsource(tui)

    check("No Layout import", "from rich.layout" not in src.lower())
    check("No Live import", "from rich.live" not in src.lower())
    check("No Panel import", "from rich.panel" not in src.lower())
    check("No use_tui parameter", "use_tui" not in src)


def test_dual_subnet_mapper():
    print("\n--- mapper.py: scans both subnets ---")
    from apiot.core.mapper import SUBNETS, NetworkMapper

    interfaces = [s["interface"] for s in SUBNETS]
    ranges = [s["range"] for s in SUBNETS]
    check("br0 in subnets", "br0" in interfaces)
    check("br_internal in subnets", "br_internal" in interfaces)
    check("100.x range present", any("100" in r for r in ranges))
    check("200.x range present", any("200" in r for r in ranges))


def test_classifier_uses_brute_force_ssh():
    print("\n--- mapper.py: classifier uses brute_force_ssh not ssh_brute_force ---")
    from apiot.core.mapper import classify

    result = classify({22}, "52:54:00:AA:BB:CC")
    check("SSH open -> brute_force_ssh in surface",
          "brute_force_ssh" in result["attack_surface"])
    check("No old ssh_brute_force name",
          "ssh_brute_force" not in result["attack_surface"])


def test_brute_force_ssh_registered():
    print("\n--- agent_loop.py: brute_force_ssh is a registered tool ---")
    from apiot.core.agent_loop import TOOLS
    check("brute_force_ssh in TOOLS", "brute_force_ssh" in TOOLS)
    check("Has fn key", callable(TOOLS["brute_force_ssh"]["fn"]))


def test_registry_has_new_tools():
    print("\n--- registry.py: new tool schemas present ---")
    from apiot.core.tools.registry import TOOL_SCHEMAS

    names = [t["function"]["name"] for t in TOOL_SCHEMAS]
    check("run_command schema exists", "run_command" in names)
    check("create_tool schema exists", "create_tool" in names)

    exploit_schema = next(t for t in TOOL_SCHEMAS if t["function"]["name"] == "execute_exploit")
    enum_vals = exploit_schema["function"]["parameters"]["properties"]["tool_name"]["enum"]
    check("brute_force_ssh in exploit enum", "brute_force_ssh" in enum_vals)


def test_run_command_dispatch():
    print("\n--- dispatcher.py: run_command executes shell commands ---")
    from apiot.core.tools.dispatcher import dispatch_tool
    import json

    result = json.loads(dispatch_tool("run_command", {"command": "echo APIOT_TEST"}))
    check("run_command returns exit_code", "exit_code" in result)
    check("run_command exit_code is 0", result.get("exit_code") == 0)
    check("run_command captures stdout", "APIOT_TEST" in result.get("stdout", ""))


def test_create_tool_dispatch():
    print("\n--- dispatcher.py: create_tool writes and loads module ---")
    from apiot.core.tools.dispatcher import dispatch_tool, DYNAMIC_DIR
    from apiot.core.agent_loop import TOOLS
    import json

    code = '''
def run(ip: str, port: int, **kwargs) -> dict:
    return {"success": True, "test": "create_tool_works", "ip": ip, "port": port}
'''
    result = json.loads(dispatch_tool("create_tool", {
        "name": "_test_tool_tmp",
        "code": code,
        "target_ip": "127.0.0.1",
        "target_port": 9999,
    }))

    check("create_tool returns success", result.get("success") is True)
    check("create_tool registered the tool", result.get("registered") is True)
    check("create_tool execution_result correct",
          result.get("execution_result", {}).get("test") == "create_tool_works")
    check("Tool registered in TOOLS", "_test_tool_tmp" in TOOLS)

    # Cleanup
    tmp_file = DYNAMIC_DIR / "_test_tool_tmp.py"
    tmp_file.unlink(missing_ok=True)
    TOOLS.pop("_test_tool_tmp", None)


def test_prompt_documents_new_capabilities():
    print("\n--- agent.py: prompt documents run_command, create_tool, dual subnet, blue team ---")
    from apiot.core.agent import SYSTEM_PROMPT

    check("Prompt mentions run_command", "run_command" in SYSTEM_PROMPT)
    check("Prompt mentions create_tool", "create_tool" in SYSTEM_PROMPT)
    check("Prompt mentions 192.168.200", "192.168.200" in SYSTEM_PROMPT)
    check("Prompt mentions brute_force_ssh", "brute_force_ssh" in SYSTEM_PROMPT)
    check("Prompt mentions both subnets", "br_internal" in SYSTEM_PROMPT)
    check("Prompt has PHASE 1 RED", "PHASE 1" in SYSTEM_PROMPT and "RED TEAM" in SYSTEM_PROMPT)
    check("Prompt has PHASE 2 BLUE", "PHASE 2" in SYSTEM_PROMPT and "BLUE TEAM" in SYSTEM_PROMPT)
    check("Prompt mentions analyze_attacks", "analyze_attacks" in SYSTEM_PROMPT)
    check("Prompt mentions apply_patch", "apply_patch" in SYSTEM_PROMPT)
    check("Prompt mentions verify_patch", "verify_patch" in SYSTEM_PROMPT)
    check("Prompt mentions VERIFIED_SECURE", "VERIFIED_SECURE" in SYSTEM_PROMPT)


def test_blue_team_tools_registered():
    print("\n--- registry.py: blue team tool schemas present ---")
    from apiot.core.tools.registry import TOOL_SCHEMAS

    names = [t["function"]["name"] for t in TOOL_SCHEMAS]
    check("analyze_attacks schema exists", "analyze_attacks" in names)
    check("apply_patch schema exists", "apply_patch" in names)
    check("verify_patch schema exists", "verify_patch" in names)
    check("list_patches schema exists", "list_patches" in names)


def test_blue_team_commands_exist():
    print("\n--- agent_loop.py: blue team command functions exist ---")
    from apiot.core.agent_loop import (
        cmd_analyze_attacks, cmd_apply_patch, cmd_verify_patch, cmd_list_patches,
    )
    check("cmd_analyze_attacks callable", callable(cmd_analyze_attacks))
    check("cmd_apply_patch callable", callable(cmd_apply_patch))
    check("cmd_verify_patch callable", callable(cmd_verify_patch))
    check("cmd_list_patches callable", callable(cmd_list_patches))


def test_compact_terminal_output():
    print("\n--- tui.py: compact terminal, full detail to log only ---")
    from io import StringIO
    from apiot.core.tui import OperatorConsole
    from rich.console import Console

    c = OperatorConsole()
    buf = StringIO()
    c.console = Console(file=buf, width=200)
    c.start()

    c.log_reasoning("This is a long reasoning block that should NOT appear in terminal")
    c.log_tool_call("stealth_check", {"ip": "192.168.100.10"})
    c.log_tool_result('{"loss_pct": 0.0, "recommendation": "proceed"}')
    c.stop()

    terminal_out = buf.getvalue()
    log_text = c.log_path.read_text()

    check("Terminal shows 'Thinking...' not full reasoning",
          "Thinking..." in terminal_out and "long reasoning block" not in terminal_out)
    check("Terminal shows compact tool call",
          "stealth_check(ip=192.168.100.10)" in terminal_out)
    has_result = "Result:" in terminal_out
    result_compact = has_result and "recommendation=proceed" in terminal_out
    check("Terminal shows compact result", result_compact)
    check("Log file has full reasoning", "long reasoning block" in log_text)
    check("Log file has full result JSON", '"loss_pct": 0.0' in log_text)

    c.log_path.unlink(missing_ok=True)


def main():
    test_missing_api_key_aborts()
    test_valid_api_key_passes()
    test_system_prompt_content()
    test_terminal_tokens_handled()
    test_lab_bridge_aborts_offline()
    test_lab_bridge_aborts_empty_topology()
    test_cli_mission_control()
    test_cli_saves_env()
    test_cli_uses_correct_vlab_endpoint()
    test_session_logging()
    test_no_tui_split_panel()
    test_dual_subnet_mapper()
    test_classifier_uses_brute_force_ssh()
    test_brute_force_ssh_registered()
    test_registry_has_new_tools()
    test_run_command_dispatch()
    test_create_tool_dispatch()
    test_prompt_documents_new_capabilities()
    test_blue_team_tools_registered()
    test_blue_team_commands_exist()
    test_compact_terminal_output()

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
