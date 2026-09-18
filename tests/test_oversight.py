#!/usr/bin/env python3
"""test_oversight.py — Unit tests for the LLM-powered Overseer reasoning layer."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["OVERSEER_ENABLED"] = "false"

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


# ── Deterministic guard tests (LLM disabled) ─────────────────────────

def test_repetition_guard():
    print("\n--- Overseer: repetition guard blocks duplicate calls ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)

    args = {"ip": "10.0.0.1", "tool_name": "brute_force_ssh"}

    for i in range(3):
        blocked, reason, _ = o.check_tool_call("execute_exploit", args)
        o.evaluate_result("execute_exploit", args, '{"success": false}', False)
        if i < 2:
            check(f"Call {i+1} not blocked", not blocked)

    blocked, reason, _ = o.check_tool_call("execute_exploit", args)
    check("Call 4 (same args) is blocked", blocked)
    check("Block reason mentions repeated", "repeated" in reason.lower() or "BLOCKED" in reason)


def test_different_args_not_blocked():
    print("\n--- Overseer: different args are not blocked ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)

    for port in [22, 23, 80]:
        args = {"ip": "10.0.0.1", "tool_name": "brute_force_ssh", "port": port}
        blocked, _, _flag = o.check_tool_call("execute_exploit", args)
        o.evaluate_result("execute_exploit", args, '{"success": false}', False)
        check(f"Port {port} not blocked", not blocked)


def test_crashed_target_blocked():
    print("\n--- Overseer: blocks exploit on crashed target ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", status="crashed")
    o = Overseer(m)

    blocked, reason, _ = o.check_tool_call("execute_exploit", {"ip": "10.0.0.1", "tool_name": "ssh"})
    check("Crashed target blocked", blocked)
    check("Reason mentions crashed", "crashed" in reason.lower())


def test_patched_attack_blocked():
    print("\n--- Overseer: blocks already-patched attack ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    sid = m.start_session("test")
    fid = m.log_finding(sid, "10.0.0.1", "r", "ssh", "brute_force_ssh", {})
    m.log_patch(fid, "10.0.0.1", "brute_force_ssh", "iptables...", {}, verified=True)
    o = Overseer(m)

    blocked, reason, _ = o.check_tool_call("execute_exploit", {"ip": "10.0.0.1", "tool_name": "brute_force_ssh"})
    check("Patched attack blocked", blocked)
    check("Reason mentions patch", "patch" in reason.lower())


def test_evaluate_result_tracks_progress():
    print("\n--- Overseer: evaluate_result tracks vulns/patches ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)

    o.evaluate_result("verify_crash", {"ip": "10.0.0.1"}, '{"verified": true}', True)
    check("vuln_count incremented on verify_crash success", o.vuln_count == 1)
    check("last_progress_turn updated", o.last_progress_turn == 1)

    o.evaluate_result("verify_shell", {"ip": "10.0.0.2"}, '{"verified": true}', True)
    check("vuln_count 2 on shell success", o.vuln_count == 2)
    check("targets_compromised tracks IP", "10.0.0.2" in o.targets_compromised)

    o.evaluate_result("apply_patch", {"ip": "10.0.0.1"}, '{"applied": true}', True)
    check("patch_count incremented", o.patch_count == 1)

    o.evaluate_result("verify_patch", {"ip": "10.0.0.1"}, '{"patch_holds": true}', True)
    check("verified_count incremented", o.verified_count == 1)


def test_evaluate_result_enriches_output():
    print("\n--- Overseer: evaluate_result appends progress line ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)
    o.targets_total = 5

    enriched = o.evaluate_result("execute_exploit",
                                  {"ip": "10.0.0.1", "tool_name": "ssh"},
                                  '{"success": false}', False)
    check("Enriched has [Progress:", "[Progress:" in enriched)
    check("Shows target count", "1/5 targets" in enriched)
    check("Shows phase", "phase=red" in enriched)


def test_failure_hint_after_multiple_fails():
    print("\n--- Overseer: hints after repeated failures (heuristic fallback) ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", device_name="OpenWrt")
    o = Overseer(m)

    for _ in range(2):
        o.evaluate_result("execute_exploit",
                          {"ip": "10.0.0.1", "tool_name": "ssh"},
                          '{"success": false}', False)

    enriched = o.evaluate_result("execute_exploit",
                                  {"ip": "10.0.0.1", "tool_name": "ssh"},
                                  '{"success": false}', False)
    check("Hint injected after 2+ fails", "[OVERSEER ANALYSIS:" in enriched)


def test_stall_detection():
    print("\n--- Overseer: stall detection injects steering (heuristic) ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer, STALL_THRESHOLD

    m = MemoryStore(":memory:")
    o = Overseer(m)

    for i in range(STALL_THRESHOLD + 1):
        o.evaluate_result("run_command", {"command": f"echo {i}"},
                          '{"exit_code": 1}', False)

    msgs = o.get_steering_messages()
    stall_msgs = [m for m in msgs if "MANDATORY DIRECTIVE" in m.get("content", "") and "findings" in m["content"].lower()]
    check("Stall steering message injected", len(stall_msgs) >= 1)


def test_phase_transition():
    print("\n--- Overseer: phase transition when all targets attempted ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)
    o.targets_total = 2

    o.evaluate_result("verify_crash", {"ip": "10.0.0.1"}, '{"verified": true}', True)
    o.evaluate_result("execute_exploit", {"ip": "10.0.0.2", "tool_name": "ssh"}, '{"success": false}', False)

    msgs = o.get_steering_messages()
    phase_msgs = [m for m in msgs if "MANDATORY DIRECTIVE" in m.get("content", "") and "blue" in m["content"].lower()]
    check("Phase transition triggered", len(phase_msgs) >= 1)
    check("Phase changed to blue", o.phase == "blue")


def test_strategy_refresh():
    print("\n--- Overseer: strategy refresh every N turns (heuristic fallback) ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer, STRATEGY_REFRESH_INTERVAL

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", device_name="Test")
    o = Overseer(m)

    for i in range(STRATEGY_REFRESH_INTERVAL):
        o.evaluate_result("run_command", {"command": f"echo {i}"}, '{"exit_code": 0}', True)

    msgs = o.get_steering_messages()
    status_msgs = [m for m in msgs if "OVERSEER STATUS" in m.get("content", "")]
    check("Strategy refresh injected (heuristic fallback)", len(status_msgs) >= 1)
    check("Status mentions turn", f"Turn {STRATEGY_REFRESH_INTERVAL}" in status_msgs[0]["content"])


def test_circuit_breaker():
    print("\n--- Overseer: circuit breaker at MAX_TURNS ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer, MAX_TURNS

    m = MemoryStore(":memory:")
    o = Overseer(m)
    o.turn = MAX_TURNS

    msgs = o.get_steering_messages()
    limit_msgs = [m for m in msgs if "Turn limit" in m.get("content", "")]
    check("Circuit breaker triggered", len(limit_msgs) >= 1)


def test_blue_tool_sets_phase():
    print("\n--- Overseer: blue team tool flips phase ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)
    check("Initial phase is red", o.phase == "red")

    o.evaluate_result("analyze_attacks", {}, '[]', True)
    check("Phase flips to blue after analyze_attacks", o.phase == "blue")


def test_target_count_from_get_actionable():
    print("\n--- Overseer: set_target_count works ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)
    o.set_target_count(7)
    check("targets_total set", o.targets_total == 7)


def test_no_memory_graceful():
    print("\n--- Overseer: works without memory store ---")
    from apiot.core.oversight import Overseer

    o = Overseer(None)
    blocked, _, _flag = o.check_tool_call("execute_exploit", {"ip": "10.0.0.1", "tool_name": "ssh"})
    check("No crash without memory", not blocked)

    enriched = o.evaluate_result("execute_exploit", {"ip": "10.0.0.1"},
                                  '{"success": false}', False)
    check("Enriched result returned", "[Progress:" in enriched)

    msgs = o.get_steering_messages()
    check("Steering messages returned (may be empty)", isinstance(msgs, list))


def test_agent_imports_overseer():
    print("\n--- Integration: agent.py uses Overseer ---")
    import inspect
    from apiot.core import agent
    src = inspect.getsource(agent.APIOTAgent.run)

    check("Overseer instantiated in run()", "Overseer(" in src)
    check("check_tool_call called", "check_tool_call" in src)
    check("evaluate_result called", "evaluate_result" in src)
    check("get_steering_messages called", "get_steering_messages" in src)
    check("set_target_count called", "set_target_count" in src)
    check("[OVERSEER] logged", "[OVERSEER]" in src)


# ── LLM integration tests (mocked) ───────────────────────────────────

def test_llm_enabled_flag():
    print("\n--- Overseer: OVERSEER_ENABLED controls LLM usage ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")

    os.environ["OVERSEER_ENABLED"] = "false"
    o = Overseer(m)
    check("LLM disabled when OVERSEER_ENABLED=false", not o._overseer_enabled)
    result = o._call_overseer_llm("test")
    check("Returns None when disabled", result is None)

    os.environ["OVERSEER_ENABLED"] = "true"
    o2 = Overseer(m)
    check("LLM enabled when OVERSEER_ENABLED=true", o2._overseer_enabled)

    os.environ["OVERSEER_ENABLED"] = "false"


def test_llm_model_configurable():
    print("\n--- Overseer: OVERSEER_MODEL is configurable ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    os.environ["OVERSEER_MODEL"] = "anthropic/claude-3-haiku"
    o = Overseer(MemoryStore(":memory:"))
    check("Custom model set", o._overseer_model == "anthropic/claude-3-haiku")

    del os.environ["OVERSEER_MODEL"]
    o2 = Overseer(MemoryStore(":memory:"))
    check("Default model is gpt-4o-mini", o2._overseer_model == "openai/gpt-4o-mini")


def test_build_state_snapshot():
    print("\n--- Overseer: _build_state_snapshot produces useful context ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", device_name="OpenWrt", services="ssh,http")
    m.upsert_device_profile("10.0.0.2", device_name="Sensor", services="coap")
    o = Overseer(m)
    o.turn = 10
    o.vuln_count = 2
    o.targets_attempted = {"10.0.0.1"}
    o.targets_compromised = {"10.0.0.1"}
    o.targets_total = 3
    o.fail_counts = {"execute_exploit:10.0.0.2": 4}
    o.call_window = [
        ("execute_exploit", "10.0.0.1", "abc"),
        ("verify_crash", "10.0.0.1", "def"),
        ("execute_exploit", "10.0.0.2", "ghi"),
    ]

    snapshot = o._build_state_snapshot("strategy_refresh", "extra context here")
    check("Snapshot contains trigger", "strategy_refresh" in snapshot)
    check("Snapshot contains turn", "Turn: 10" in snapshot)
    check("Snapshot contains phase", "Phase: red" in snapshot)
    check("Snapshot contains vuln count", "2 vulns" in snapshot)
    check("Snapshot contains target stats", "1/3 attempted" in snapshot)
    check("Snapshot contains compromised", "1 compromised" in snapshot)
    check("Snapshot contains recent calls", "Recent tool calls" in snapshot)
    check("Snapshot contains high-failure", "High-failure targets" in snapshot)
    check("Snapshot contains device profiles", "Device profiles" in snapshot)
    check("Snapshot contains extra context", "extra context here" in snapshot)
    check("Snapshot shows services", "ssh,http" in snapshot or "services=" in snapshot)


def test_llm_called_on_strategy_refresh():
    print("\n--- Overseer: LLM called on strategy refresh when enabled ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer, STRATEGY_REFRESH_INTERVAL

    os.environ["OVERSEER_ENABLED"] = "true"
    os.environ["OPENROUTER_API_KEY"] = "test-key-fake"

    m = MemoryStore(":memory:")
    o = Overseer(m)

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "1. Scan 10.0.0.2 with nmap -sV\n2. Try coap_option_overflow on 10.0.0.3"

    for i in range(STRATEGY_REFRESH_INTERVAL):
        o.evaluate_result("run_command", {"command": f"echo {i}"}, '{"exit_code": 0}', True)

    with patch.object(o, "_get_llm_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_client_fn.return_value = mock_client

        msgs = o.get_steering_messages()

        check("LLM create() was called", mock_client.chat.completions.create.called)
        call_args = mock_client.chat.completions.create.call_args
        check("System prompt sent to LLM", call_args.kwargs["messages"][0]["role"] == "system")
        check("State snapshot sent as user message", "strategy_refresh" in call_args.kwargs["messages"][1]["content"])
        check("max_tokens set", call_args.kwargs["max_tokens"] == 300)
        check("temperature is low", call_args.kwargs["temperature"] == 0.3)

        overseer_msgs = [m for m in msgs if "OVERSEER" in m.get("content", "")]
        check("LLM response injected as steering", len(overseer_msgs) >= 1)
        check("LLM response content present", "coap_option_overflow" in overseer_msgs[0]["content"])

    os.environ["OVERSEER_ENABLED"] = "false"
    os.environ.pop("OPENROUTER_API_KEY", None)


def test_llm_called_on_stall():
    print("\n--- Overseer: LLM called on stall detection when enabled ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer, STALL_THRESHOLD

    os.environ["OVERSEER_ENABLED"] = "true"
    os.environ["OPENROUTER_API_KEY"] = "test-key-fake"

    m = MemoryStore(":memory:")
    o = Overseer(m)

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "1. Switch to UDP probing on 10.0.0.3:5683\n2. Use create_tool for MQTT exploit"

    for i in range(STALL_THRESHOLD + 1):
        o.evaluate_result("run_command", {"command": f"echo {i}"},
                          '{"exit_code": 1}', False)

    with patch.object(o, "_get_llm_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_client_fn.return_value = mock_client

        msgs = o.get_steering_messages()

        check("LLM called for stall", mock_client.chat.completions.create.called)
        stall_msgs = [m for m in msgs if "OVERSEER" in m.get("content", "")]
        check("LLM stall analysis injected", len(stall_msgs) >= 1)
        check("LLM content in message", "MQTT" in stall_msgs[0]["content"])

    os.environ["OVERSEER_ENABLED"] = "false"
    os.environ.pop("OPENROUTER_API_KEY", None)


def test_llm_called_on_failure_hint():
    print("\n--- Overseer: LLM called for failure analysis when enabled ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    os.environ["OVERSEER_ENABLED"] = "true"
    os.environ["OPENROUTER_API_KEY"] = "test-key-fake"

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", device_name="OpenWrt", services="ssh,http")
    o = Overseer(m)

    for _ in range(2):
        o.evaluate_result("execute_exploit",
                          {"ip": "10.0.0.1", "tool_name": "ssh"},
                          '{"success": false}', False)

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "SSH creds likely non-default. Try http_cmd_injection on port 80."

    with patch.object(o, "_get_llm_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_client_fn.return_value = mock_client

        enriched = o.evaluate_result("execute_exploit",
                                      {"ip": "10.0.0.1", "tool_name": "ssh"},
                                      '{"success": false}', False)

        check("LLM called for failure analysis", mock_client.chat.completions.create.called)
        call_args = mock_client.chat.completions.create.call_args
        check("Trigger is failure_analysis", "failure_analysis" in call_args.kwargs["messages"][1]["content"])
        check("LLM analysis in enriched result", "http_cmd_injection" in enriched)
        check("OVERSEER ANALYSIS prefix present", "[OVERSEER ANALYSIS:" in enriched)

    os.environ["OVERSEER_ENABLED"] = "false"
    os.environ.pop("OPENROUTER_API_KEY", None)


def test_llm_failure_falls_back_to_heuristic():
    print("\n--- Overseer: LLM failure falls back to heuristic ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer, STRATEGY_REFRESH_INTERVAL

    os.environ["OVERSEER_ENABLED"] = "true"
    os.environ["OPENROUTER_API_KEY"] = "test-key-fake"

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", device_name="Test")
    o = Overseer(m)

    for i in range(STRATEGY_REFRESH_INTERVAL):
        o.evaluate_result("run_command", {"command": f"echo {i}"}, '{"exit_code": 0}', True)

    with patch.object(o, "_get_llm_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API timeout")
        mock_client_fn.return_value = mock_client

        msgs = o.get_steering_messages()

        check("LLM was attempted", mock_client.chat.completions.create.called)
        status_msgs = [m for m in msgs if "OVERSEER STATUS" in m.get("content", "")]
        check("Heuristic fallback used on LLM failure", len(status_msgs) >= 1)

    os.environ["OVERSEER_ENABLED"] = "false"
    os.environ.pop("OPENROUTER_API_KEY", None)


def test_llm_phase_transition_can_override():
    print("\n--- Overseer: LLM can recommend continuing red team ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    os.environ["OVERSEER_ENABLED"] = "true"
    os.environ["OPENROUTER_API_KEY"] = "test-key-fake"

    m = MemoryStore(":memory:")
    o = Overseer(m)
    o.targets_total = 1

    o.evaluate_result("verify_crash", {"ip": "10.0.0.1"}, '{"verified": true}', True)

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = (
        "1. Continue red team — run post-exploitation on 10.0.0.1 via remote_exec\n"
        "2. Enumerate internal services before transitioning"
    )

    with patch.object(o, "_get_llm_client") as mock_client_fn:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_client_fn.return_value = mock_client

        msgs = o.get_steering_messages()

        check("Phase stays red when LLM says continue", o.phase == "red")
        check("LLM directive injected", any("remote_exec" in m.get("content", "") for m in msgs))

    os.environ["OVERSEER_ENABLED"] = "false"
    os.environ.pop("OPENROUTER_API_KEY", None)


def test_no_api_key_graceful():
    print("\n--- Overseer: no API key = graceful fallback ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    os.environ["OVERSEER_ENABLED"] = "true"
    os.environ.pop("OPENROUTER_API_KEY", None)

    m = MemoryStore(":memory:")
    o = Overseer(m)

    result = o._call_overseer_llm("test")
    check("Returns None without API key", result is None)

    os.environ["OVERSEER_ENABLED"] = "false"


def test_overseer_system_prompt_exists():
    print("\n--- Overseer: system prompt is well-formed ---")
    from apiot.core.oversight import _OVERSEER_SYSTEM

    check("System prompt is non-empty", len(_OVERSEER_SYSTEM) > 100)
    check("Prompt mentions directives", "directive" in _OVERSEER_SYSTEM.lower())
    check("Prompt mentions specific", "specific" in _OVERSEER_SYSTEM.lower())
    check("Prompt mentions 150 words", "150" in _OVERSEER_SYSTEM)
    check("Prompt mentions diversity", "diversity" in _OVERSEER_SYSTEM.lower())


def test_wrap_directive():
    print("\n--- Overseer: _wrap_directive produces mandatory format ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)
    wrapped = o._wrap_directive("Use create_tool for MQTT exploit on 10.0.0.1")
    check("Has MANDATORY DIRECTIVE", "MANDATORY DIRECTIVE" in wrapped)
    check("Has MUST follow", "MUST follow" in wrapped)
    check("Original content preserved", "create_tool" in wrapped)


def test_diversity_check_fires():
    print("\n--- Overseer: diversity check detects monotonic brute_force_ssh ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)

    for i, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
                             "10.0.0.5", "10.0.0.6", "10.0.0.7"]):
        o.evaluate_result("brute_force_ssh", {"ip": ip},
                          '{"success": true, "credential": "root:root"}', True)

    msgs = o.get_steering_messages()
    diversity_msgs = [m for m in msgs if "MANDATORY DIRECTIVE" in m.get("content", "")
                      and ("brute_force_ssh" in m["content"] or "DIFFERENT" in m["content"])]
    check("Diversity directive injected", len(diversity_msgs) >= 1)


def test_diversity_check_does_not_fire_when_diverse():
    print("\n--- Overseer: diversity check silent when tools are varied ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)

    tools = ["execute_exploit", "brute_force_ssh", "verify_crash",
             "remote_exec", "execute_exploit", "create_tool", "brute_force_ssh"]
    for i, tool in enumerate(tools):
        o.evaluate_result(tool, {"ip": f"10.0.0.{i+1}"},
                          '{"success": true}', True)

    msgs = o.get_steering_messages()
    diversity_msgs = [m for m in msgs if "STOP using" in m.get("content", "")]
    check("No diversity alert when tools are varied", len(diversity_msgs) == 0)


def test_check_tool_call_returns_3tuple():
    print("\n--- Overseer: check_tool_call returns 3-tuple (EXT4) ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    o = Overseer(m)

    result = o.check_tool_call("execute_exploit", {"ip": "10.0.0.1", "tool_name": "ssh"})
    check("Returns 3-tuple", len(result) == 3)
    blocked, reason, flag = result
    check("Not blocked initially", not blocked)
    check("Flag is string", isinstance(flag, str))
    check("Flag is 'none' with no pending", flag == "none")


def test_overseer_flag_on_blocked_calls():
    print("\n--- Overseer: overseer_flag set correctly on blocked calls (EXT4) ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.oversight import Overseer

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", status="crashed")
    o = Overseer(m)

    _, _, flag = o.check_tool_call("execute_exploit", {"ip": "10.0.0.1", "tool_name": "ssh"})
    check("blocked_crashed flag set", flag == "blocked_crashed")

    m2 = MemoryStore(":memory:")
    o2 = Overseer(m2)
    args = {"ip": "10.0.0.2", "tool_name": "brute_force_ssh"}
    for _ in range(3):
        o2.check_tool_call("execute_exploit", args)
        o2.evaluate_result("execute_exploit", args, '{"success": false}', False)
    _, _, flag2 = o2.check_tool_call("execute_exploit", args)
    check("blocked_repeat flag set", flag2 == "blocked_repeat")


def test_no_overseer_agent_mode():
    print("\n--- EXT1: APIOTAgent with overseer_enabled=False skips all overseer calls ---")
    import inspect
    from apiot.core.agent import APIOTAgent

    # Verify __init__ accepts overseer_enabled
    import inspect as _inspect
    sig = _inspect.signature(APIOTAgent.__init__)
    check("overseer_enabled param exists", "overseer_enabled" in sig.parameters)
    check("overseer_enabled defaults to True", sig.parameters["overseer_enabled"].default is True)

    src = inspect.getsource(APIOTAgent.run)
    check("overseer_enabled guard present in run()", "overseer_enabled" in src)
    check("--no-overseer logged", "DISABLED" in src)


def test_agent_prompt_mentions_overseer_priority():
    print("\n--- Integration: agent system prompt prioritizes Overseer ---")
    from apiot.core.agent import SYSTEM_PROMPT

    check("Prompt mentions OVERSEER", "[OVERSEER]" in SYSTEM_PROMPT)
    check("Prompt says HIGHEST PRIORITY", "HIGHEST PRIORITY" in SYSTEM_PROMPT)
    check("Prompt says MUST follow", "MUST follow" in SYSTEM_PROMPT)
    check("Prompt says ABANDON your plan", "ABANDON your plan" in SYSTEM_PROMPT)


def main():
    test_repetition_guard()
    test_different_args_not_blocked()
    test_crashed_target_blocked()
    test_patched_attack_blocked()
    test_evaluate_result_tracks_progress()
    test_evaluate_result_enriches_output()
    test_failure_hint_after_multiple_fails()
    test_stall_detection()
    test_phase_transition()
    test_strategy_refresh()
    test_circuit_breaker()
    test_blue_tool_sets_phase()
    test_target_count_from_get_actionable()
    test_no_memory_graceful()
    test_agent_imports_overseer()
    # LLM integration tests
    test_llm_enabled_flag()
    test_llm_model_configurable()
    test_build_state_snapshot()
    test_llm_called_on_strategy_refresh()
    test_llm_called_on_stall()
    test_llm_called_on_failure_hint()
    test_llm_failure_falls_back_to_heuristic()
    test_llm_phase_transition_can_override()
    test_no_api_key_graceful()
    test_overseer_system_prompt_exists()
    test_wrap_directive()
    test_diversity_check_fires()
    test_diversity_check_does_not_fire_when_diverse()
    test_agent_prompt_mentions_overseer_priority()
    # EXT1 + EXT4 tests
    test_check_tool_call_returns_3tuple()
    test_overseer_flag_on_blocked_calls()
    test_no_overseer_agent_mode()

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
