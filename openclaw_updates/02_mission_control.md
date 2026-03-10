# 02 — Mission Control (Interactive Mission Planner)

## Problem

The current CLI has a flat "Autonomous Red Team" or "Manual CLI" mode selector. There is no concept of mission history, device-specific targeting, or iterative engagement. The agent attacks everything every time. The user has no way to say "focus on this device" or "try novel approaches on this target" or "skip devices already fully tested."

## What OpenClaw Does

OpenClaw's session system lets users define context via workspace files (`BOOT.md`, `SOUL.md`, `AGENTS.md`), and the agent accumulates knowledge across sessions. The hook system fires at session start/reset, loading prior context automatically. Skills provide domain-specific procedural knowledge that guides behavior.

## How APIOT Should Implement This

### Replace Step 6 (Mode Selection) with Mission Control

The CLI should present a rich mission briefing before launching the agent:

```
╭─────────────────────────────────────────────╮
│          APIOT — Mission Control            │
╰─────────────────────────────────────────────╯

  Network History (3 prior sessions):
  ┌──────────────────┬──────────────┬──────────┬───────────────────┐
  │ Device           │ IP           │ Status   │ Last Tested       │
  ├──────────────────┼──────────────┼──────────┼───────────────────┤
  │ DVRF Router      │ 192.168.100.10│ PWNED   │ 2026-03-09 15:47 │
  │ Segmented GW     │ 192.168.100.24│ PWNED   │ 2026-03-09 15:47 │
  │ Smart Meter      │ 192.168.200.35│ PATCHED │ 2026-03-09 15:50 │
  │ Debian ARM #1    │ 192.168.200.20│ PWNED   │ 2026-03-09 15:48 │
  └──────────────────┴──────────────┴──────────┴───────────────────┘

  Active patches: 1 (CoAP length filter on port 5683)
  Open vulnerabilities: 5 (SSH default creds)

  Mission Modes:
  1  Full Purple Team   — Red + Blue on all devices
  2  Targeted Red Team  — Select specific device(s) to attack
  3  Novel Exploitation — Re-engage previously tested device with new approaches
  4  Blue Team Only     — Analyze + patch + verify existing findings
  5  Reconnaissance     — Scan only, no exploitation
  6  Manual CLI Harness — You drive tool commands
```

### Targeted Mode

When "Targeted Red Team" is selected, show device list and let user pick one or more. The agent prompt gets an instruction: "Focus exclusively on [selected IPs]. Use novel attack methods — do NOT repeat approaches already tried (see history below)."

### Novel Exploitation Mode

Injects the full attack history for the selected device and instructs the agent: "All previous attacks are listed below. You MUST try different approaches. Use run_command for manual reconnaissance, create_tool to build custom exploits, and explore service behaviors not covered by existing tools."

### Mission Context Injection

Before launching the agent, the CLI builds a `mission_context` string from the memory store and prepends it to the conversation:

```python
mission_context = build_mission_context(
    mode="novel",
    target_ips=["192.168.100.10"],
    memory=MemoryStore(),
)
# Contains: device profiles, past findings, past tool calls, active patches
agent.messages.insert(1, {"role": "user", "content": mission_context})
```

## Files to Modify

- `core/cli.py` — replace `_select_mode()` with full mission control UI; add `_show_network_history()`, `_select_targets()`, `_build_mission_context()`
- `core/agent.py` — accept `mission_context` parameter in `run()` and inject into conversation
- Depends on: `01_persistent_memory.md` for the memory store

## Estimated Effort

Medium. Mostly CLI UI work and prompt engineering. The mission context builder is the key piece.

## Implementation Notes

Executed. Files modified:
- `core/cli.py` — Complete rewrite with Mission Control screen showing network history, 5 mission modes (full_purple, targeted_red, novel, blue_only, recon), device targeting, and memory store integration.
- `core/agent.py` — Accept api_key, model, memory in __init__; accept mode, target_ips in run(); inject mission context via build_mission_context when MemoryStore is used.
