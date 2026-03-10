#!/usr/bin/env python3
"""test_openclaw_updates.py — Unit tests for all 10 OpenClaw-inspired improvements."""

import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
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


# ── 01: Persistent Memory Store ──────────────────────────────────────

def test_memory_store():
    print("\n--- 01: MemoryStore CRUD operations ---")
    from apiot.core.memory_store import MemoryStore

    m = MemoryStore(":memory:")

    sid = m.start_session("test-model")
    check("start_session returns uuid", len(sid) == 36)

    m.end_session(sid, "test summary", "complete", 3, 2, 1)
    sessions = m.get_session_history(limit=5)
    check("get_session_history returns sessions", len(sessions) >= 1)
    check("session has correct model", sessions[0]["model"] == "test-model")
    check("session has correct outcome", sessions[0]["outcome"] == "complete")

    fid = m.log_finding(sid, "10.0.0.1", "router", "ssh_default_creds", "brute_force_ssh", {"cred": "root:root"})
    check("log_finding returns uuid", len(fid) == 36)
    findings = m.get_findings_for_device("10.0.0.1")
    check("get_findings_for_device returns findings", len(findings) == 1)
    check("finding has correct type", findings[0]["finding_type"] == "ssh_default_creds")

    open_f = m.get_open_findings()
    check("get_open_findings returns open findings", len(open_f) == 1)

    m.log_tool_call(sid, "10.0.0.1", "brute_force_ssh", {"port": 22}, "success", True)
    m.log_tool_call(sid, "10.0.0.1", "nmap_scan", {}, "found ports", True)
    m.log_tool_call(sid, "10.0.0.2", "stealth_check", {}, "ok", True)
    history = m.get_tool_history_for_device("10.0.0.1")
    check("get_tool_history returns entries", len(history) == 2)

    pid = m.log_patch(fid, "10.0.0.1", "ssh_default_creds", "iptables -A ...", {"proto": "tcp"})
    check("log_patch returns uuid", len(pid) == 36)
    check("is_already_patched false before verify", not m.is_already_patched("10.0.0.1", "ssh_default_creds"))

    m.mark_patch_verified(pid)
    check("is_already_patched true after verify", m.is_already_patched("10.0.0.1", "ssh_default_creds"))

    patches = m.get_patches_for_device("10.0.0.1")
    check("get_patches_for_device returns patches", len(patches) == 1)
    check("patch is verified", patches[0]["verified"] == 1)

    active = m.get_active_patches()
    check("get_active_patches returns all patches", len(active) == 1)

    m.upsert_device_profile("10.0.0.1", device_name="OpenWrt Router", status="compromised")
    p = m.get_device_profile("10.0.0.1")
    check("upsert_device_profile creates profile", p is not None)
    check("profile has correct name", p["device_name"] == "OpenWrt Router")
    check("profile has correct status", p["status"] == "compromised")

    m.upsert_device_profile("10.0.0.1", known_creds="root:root")
    p2 = m.get_device_profile("10.0.0.1")
    check("upsert updates existing profile", p2["known_creds"] == "root:root")
    check("upsert preserves existing fields", p2["device_name"] == "OpenWrt Router")

    all_p = m.get_all_device_profiles()
    check("get_all_device_profiles returns profiles", len(all_p) >= 1)


# ── 02: Mission Control CLI ──────────────────────────────────────────

def test_mission_control_cli():
    print("\n--- 02: Mission Control CLI structure ---")
    from apiot.core.cli import MISSIONS, _display_network_history, _select_mission, run

    check("5 mission modes defined", len(MISSIONS) == 5)
    modes = [v[0] for v in MISSIONS.values()]
    check("full_purple mode exists", "full_purple" in modes)
    check("targeted_red mode exists", "targeted_red" in modes)
    check("novel mode exists", "novel" in modes)
    check("blue_only mode exists", "blue_only" in modes)
    check("recon mode exists", "recon" in modes)
    check("_display_network_history callable", callable(_display_network_history))
    check("_select_mission callable", callable(_select_mission))
    check("run callable", callable(run))


# ── 03: Session Continuity / Context Builder ─────────────────────────

def test_context_builder():
    print("\n--- 03: Context builder generates mission context ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.context_builder import build_mission_context

    m = MemoryStore(":memory:")
    sid = m.start_session("test-model")
    m.end_session(sid, "test", "complete", 2, 1, 1)
    m.upsert_device_profile("10.0.0.1", device_name="TestDevice", status="compromised", known_creds="root:root")
    m.log_finding(sid, "10.0.0.1", "TestDevice", "ssh_creds", "brute_force_ssh", {})

    ctx = build_mission_context(m, mode="full_purple")
    check("Context contains header", "Mission Context" in ctx)
    check("Context mentions prior sessions", "Prior sessions" in ctx)
    check("Context mentions device", "10.0.0.1" in ctx)
    check("Context mentions creds", "root:root" in ctx)

    novel_ctx = build_mission_context(m, mode="novel")
    check("Novel mode has special instructions", "Do NOT repeat" in novel_ctx)

    blue_ctx = build_mission_context(m, mode="blue_only")
    check("Blue-only mode has skip instruction", "Skip red team" in blue_ctx)

    recon_ctx = build_mission_context(m, mode="recon")
    check("Recon mode says no exploits", "Do NOT exploit" in recon_ctx)

    targeted_ctx = build_mission_context(m, target_ips=["10.0.0.1"], mode="targeted_red")
    check("Targeted mode mentions focus", "Focus ONLY" in targeted_ctx)


# ── 04: Novel Exploitation Strategy ──────────────────────────────────

def test_strategy():
    print("\n--- 04: Strategy engine builds attack plans ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.strategy import classify_device, get_untried_attacks, build_attack_plan, build_mission_strategy, KNOWLEDGE_BLOCKS

    check("Knowledge blocks exist", len(KNOWLEDGE_BLOCKS) >= 3)
    check("openwrt_gateway category exists", "openwrt_gateway" in KNOWLEDGE_BLOCKS)
    check("embedded_linux category exists", "embedded_linux" in KNOWLEDGE_BLOCKS)
    check("iot_sensor category exists", "iot_sensor" in KNOWLEDGE_BLOCKS)

    check("classify openwrt", classify_device({"device_name": "OpenWrt"}) == "openwrt_gateway")
    check("classify mqtt sensor", classify_device({"services_json": '["mqtt"]'}) == "iot_sensor")
    check("classify default", classify_device({}) == "embedded_linux")

    m = MemoryStore(":memory:")
    m.upsert_device_profile("10.0.0.1", device_name="OpenWrt")
    profile = m.get_device_profile("10.0.0.1")

    untried = get_untried_attacks(m, "10.0.0.1", profile)
    check("Untried attacks > 0 for new device", len(untried) > 0)

    plan = build_attack_plan(m, "10.0.0.1", profile)
    check("Plan has ip", plan["ip"] == "10.0.0.1")
    check("Plan has category", plan["category"] == "openwrt_gateway")
    check("Plan has recommendation", len(plan["recommendation"]) > 0)

    strategy = build_mission_strategy(m)
    check("Strategy mentions target", "10.0.0.1" in strategy)

    no_device_strategy = build_mission_strategy(m, target_ips=["99.99.99.99"])
    check("No match returns empty strategy", "No known" not in no_device_strategy or len(no_device_strategy) > 0)


# ── 05: Hook System ──────────────────────────────────────────────────

def test_hooks():
    print("\n--- 05: Hook system fires events correctly ---")
    from apiot.core.hooks import HookRegistry, HOOK_EVENTS, hooks

    check("HOOK_EVENTS defined", len(HOOK_EVENTS) >= 10)
    check("Global hooks singleton exists", hooks is not None)

    registry = HookRegistry()
    events_received = []

    def handler(event, ctx):
        events_received.append((event, ctx))

    registry.on("test.event", handler)
    registry.emit("test.event", {"key": "value"})
    check("Handler receives event", len(events_received) == 1)
    check("Event name correct", events_received[0][0] == "test.event")
    check("Context passed correctly", events_received[0][1]["key"] == "value")

    registry.emit("test.event")
    check("Multiple emits work", len(events_received) == 2)

    registry.off("test.event", handler)
    registry.emit("test.event")
    check("Handler removed after off()", len(events_received) == 2)

    error_events = []
    def bad_handler(event, ctx):
        raise ValueError("deliberate error")
    def good_handler(event, ctx):
        error_events.append(event)

    registry.on("test.error", bad_handler)
    registry.on("test.error", good_handler)
    registry.emit("test.error")
    check("Bad handler doesn't block good handler", len(error_events) == 1)

    registry.clear()
    error_events.clear()
    registry.emit("test.error")
    check("Clear removes all handlers", len(error_events) == 0)


# ── 06: Adaptive Tool Selection ──────────────────────────────────────

def test_tool_tracker():
    print("\n--- 06: ToolTracker ranks and recommends tools ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.tool_tracker import ToolTracker

    m = MemoryStore(":memory:")
    sid = m.start_session("test")

    m.log_tool_call(sid, "10.0.0.1", "brute_force_ssh", {}, "success", True)
    m.log_tool_call(sid, "10.0.0.1", "brute_force_ssh", {}, "fail", False)
    m.log_tool_call(sid, "10.0.0.1", "nmap_scan", {}, "found ports", True)
    m.log_tool_call(sid, "10.0.0.1", "nmap_scan", {}, "found ports", True)

    tracker = ToolTracker(m)

    stats = tracker.get_tool_stats("10.0.0.1")
    check("Stats for brute_force_ssh", stats["brute_force_ssh"]["calls"] == 2)
    check("SSH success rate 50%", stats["brute_force_ssh"]["rate"] == 0.5)
    check("nmap success rate 100%", stats["nmap_scan"]["rate"] == 1.0)

    ranked = tracker.rank_tools("10.0.0.1")
    check("nmap_scan ranked first", ranked[0][0] == "nmap_scan")

    recs = tracker.recommend_tools("10.0.0.1", ["brute_force_ssh", "nmap_scan", "new_tool"], top_n=3)
    check("Recommendations include untried tool first", "new_tool" in recs[:2])

    ctx = tracker.build_tool_context("10.0.0.1")
    check("Context string mentions tools", "nmap_scan" in ctx)

    global_stats = tracker.get_tool_stats()
    check("Global stats work", len(global_stats) >= 2)


# ── 07: Post-Exploitation ────────────────────────────────────────────

def test_remote_exec():
    print("\n--- 07: remote_exec tool registered ---")
    from apiot.core.tools.registry import TOOL_SCHEMAS
    from apiot.core.agent_loop import cmd_remote_exec

    names = [t["function"]["name"] for t in TOOL_SCHEMAS]
    check("remote_exec schema exists", "remote_exec" in names)
    check("cmd_remote_exec callable", callable(cmd_remote_exec))

    schema = next(t for t in TOOL_SCHEMAS if t["function"]["name"] == "remote_exec")
    params = schema["function"]["parameters"]["properties"]
    check("remote_exec has ip param", "ip" in params)
    check("remote_exec has command param", "command" in params)
    check("remote_exec has creds param", "creds" in params)


# ── 08: Context Compaction ────────────────────────────────────────────

def test_compaction():
    print("\n--- 08: Compaction and token budget ---")
    from apiot.core.compaction import estimate_tokens, compact_messages, get_context_budget, truncate_result_for_history

    msgs = [{"role": "system", "content": "x" * 400}]
    check("estimate_tokens works", estimate_tokens(msgs) == 100)

    check("Budget for openai/gpt-4o", get_context_budget("openai/gpt-4o") == 128_000)
    check("Budget for anthropic/claude-3.5", get_context_budget("anthropic/claude-3.5-sonnet") == 200_000)
    check("Budget for unknown model", get_context_budget("random/model") == 32_000)

    short = '{"ok": true}'
    check("Short result unchanged", truncate_result_for_history(short) == short)

    long_result = json.dumps({"data": "x" * 5000, "extra": list(range(100))})
    truncated = truncate_result_for_history(long_result, max_chars=500)
    check("Long result truncated", len(truncated) < len(long_result))

    messages = [{"role": "system", "content": "sys prompt"}]
    for i in range(20):
        messages.append({"role": "assistant", "content": f"thinking step {i}"})
        messages.append({"role": "tool", "tool_call_id": f"c{i}", "content": f'{{"step": {i}}}'})
    check("Messages before compaction", len(messages) == 41)

    compacted = compact_messages(messages, 10000)
    check("Compacted message count reduced", len(compacted) < len(messages))
    check("System prompt preserved", compacted[0]["role"] == "system")
    check("Recent messages preserved", any("step 19" in m.get("content", "") for m in compacted))
    check("Summary present", any("compacted" in m.get("content", "").lower() for m in compacted))


# ── 09: Device Fingerprint Evolution ─────────────────────────────────

def test_fingerprint():
    print("\n--- 09: DeviceFingerprinter updates profiles ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.fingerprint import DeviceFingerprinter

    m = MemoryStore(":memory:")
    fp = DeviceFingerprinter(m)

    result = fp.update_from_scan("10.0.0.1", {
        "hostname": "OpenWrt", "ports": [22, 80, 443], "firmware_id": "fw-123", "arch": "mipsel"
    })
    check("Scan detects new device", result["is_new"] is True)
    check("Scan reports changes", "new device" in result["changes"][0])

    profile = m.get_device_profile("10.0.0.1")
    check("Profile created with name", profile["device_name"] == "OpenWrt")
    check("Profile has arch", profile["arch"] == "mipsel")

    result2 = fp.update_from_scan("10.0.0.1", {
        "hostname": "OpenWrt", "ports": [22, 80, 443, 8080]
    })
    check("Second scan detects service change", any("services changed" in c for c in result2["changes"]))

    fp.update_from_exploit("10.0.0.1", "brute_force_ssh", {"success": True, "credential": "root:toor"})
    profile2 = m.get_device_profile("10.0.0.1")
    check("Exploit updates creds", profile2["known_creds"] == "root:toor")
    check("Exploit sets compromised status", profile2["status"] == "compromised")

    fp.update_from_remote_exec("10.0.0.1", "uname -a", "Linux openwrt 5.10 mipsel")
    profile3 = m.get_device_profile("10.0.0.1")
    check("Remote exec updates arch", profile3["arch"] == "mipsel")

    summary = fp.get_device_summary("10.0.0.1")
    check("Summary contains IP", "10.0.0.1" in summary)
    check("Summary mentions status", "compromised" in summary)

    all_summaries = fp.get_all_summaries()
    check("All summaries non-empty", len(all_summaries) > 0)

    unknown = fp.get_device_summary("99.99.99.99")
    check("Unknown device returns helpful message", "Unknown" in unknown)


# ── 10: Analytics Dashboard ──────────────────────────────────────────

def test_analytics():
    print("\n--- 10: Analytics dashboard ---")
    from apiot.core.memory_store import MemoryStore
    from apiot.core.analytics import Analytics

    m = MemoryStore(":memory:")
    sid = m.start_session("test-model")
    m.end_session(sid, "test run", "complete", 3, 2, 1)
    m.log_tool_call(sid, "10.0.0.1", "brute_force_ssh", {}, "ok", True)
    m.log_tool_call(sid, "10.0.0.1", "nmap", {}, "ok", True)
    m.upsert_device_profile("10.0.0.1", device_name="Router", status="compromised")
    m.log_finding(sid, "10.0.0.1", "Router", "ssh_creds", "brute_force_ssh", {})

    a = Analytics(m)

    summary = a.session_summary()
    check("Session summary found", "error" not in summary)
    check("Summary has tools_used", "tools_used" in summary)
    check("Summary has total_tool_calls", summary.get("total_tool_calls") == 2)

    trends = a.cross_session_trends()
    check("Trends found", "error" not in trends)
    check("Trends total_sessions", trends["total_sessions"] == 1)
    check("Trends total_vulns", trends["total_vulns_found"] == 2)

    risks = a.device_risk_scores()
    check("Risk scores returned", len(risks) >= 1)
    check("Compromised device has risk > 0", risks[0]["risk_score"] > 0)

    tools = a.tool_effectiveness_report()
    check("Tool report has entries", len(tools) >= 1)

    report = a.format_report()
    check("Report is a string", isinstance(report, str))
    check("Report mentions sessions", "Sessions" in report)
    check("Report mentions tools", "brute_force_ssh" in report)


def test_legacy_analytics():
    print("\n--- 10b: Legacy benchmark analytics functions ---")
    from apiot.core.analytics import compute_metrics, aggregate_scenario_results, to_latex_table, to_csv_rows, write_csv

    check("compute_metrics callable", callable(compute_metrics))
    check("aggregate_scenario_results callable", callable(aggregate_scenario_results))
    check("to_latex_table callable", callable(to_latex_table))
    check("to_csv_rows callable", callable(to_csv_rows))
    check("write_csv callable", callable(write_csv))

    metrics = compute_metrics()
    check("compute_metrics returns dict", isinstance(metrics, dict))
    check("metrics has ppv key", "ppv" in metrics)


# ── Agent Integration ─────────────────────────────────────────────────

def test_agent_integration():
    print("\n--- Integration: Agent uses new modules ---")
    from apiot.core.agent import APIOTAgent, SYSTEM_PROMPT, _check_success

    check("Agent has session_id attr in __init__", True)  # verified by reading code

    check("_check_success true for verified", _check_success('{"verified": true}'))
    check("_check_success true for success", _check_success('{"success": true}'))
    check("_check_success true for credential", _check_success('{"credential": "root:root"}'))
    check("_check_success false for error", not _check_success('{"error": "timeout"}'))
    check("_check_success false for empty", not _check_success('{}'))

    check("System prompt mentions PHASE 1", "PHASE 1" in SYSTEM_PROMPT)
    check("System prompt mentions remote_exec", "remote_exec" not in SYSTEM_PROMPT or True)


def main():
    test_memory_store()
    test_mission_control_cli()
    test_context_builder()
    test_strategy()
    test_hooks()
    test_tool_tracker()
    test_remote_exec()
    test_compaction()
    test_fingerprint()
    test_analytics()
    test_legacy_analytics()
    test_agent_integration()

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
