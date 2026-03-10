# 03 — Session Continuity and Context Injection

## Problem

Each APIOT run starts with a blank conversation. The system prompt is static — it never changes based on what happened before. The agent has no way to know:
- What it did in the last session
- What vulnerabilities are still open
- What patches are active
- What attack approaches already failed on a specific device

This means the agent wastes time repeating successful attacks and never learns from failures.

## What OpenClaw Does

OpenClaw's context engine has a `bootstrap()` method that loads workspace files into the prompt at session start. The `session-memory` hook automatically saves a summary of each session as a markdown file in `memory/`, which gets indexed and retrieved in future sessions via embedding search. The `assemble()` method builds context within a token budget, and `compact()` summarizes old turns to fit.

## How APIOT Should Implement This

### Session Lifecycle

```
START
  │
  ├── Load memory store (01_persistent_memory)
  ├── Build context injection block:
  │     ├── Network history summary (devices, statuses)
  │     ├── Open findings (unpatched vulns)
  │     ├── Active patches (with rules)
  │     ├── For targeted devices: full attack history
  │     └── Session objective (from mission control)
  │
  ├── Inject as first user message (before agent starts)
  │
  ├── Agent runs... (tool calls logged in real-time)
  │
  └── Session end:
        ├── Generate session summary (template or LLM)
        ├── Update device profiles
        ├── Store findings + patches
        └── Write session record
```

### Context Injection Format

The injected context should be a structured block the agent can parse:

```
=== APIOT Mission Context ===

Session objective: Novel exploitation of 192.168.100.10 (DVRF Router)

Device profile:
  IP: 192.168.100.10
  Firmware: dvrf_v03 (MIPS, Damn Vulnerable Router Firmware v0.3)
  Known credentials: root:root (SSH, found session #1)
  Open ports: 22/tcp (SSH)
  Prior attacks:
    - brute_force_ssh → SUCCESS (root:root) [session #1, #2, #3]
    - brute_force_telnet → FAILED (port closed) [session #1]
    - http_cmd_injection → FAILED (port 80 closed) [session #1]

Active patches: none for this device

Instruction: You have already found SSH credentials. Do NOT repeat brute_force_ssh. 
Use run_command to explore the device further (e.g., nmap deeper scan, service 
enumeration, vulnerability scanning). Use create_tool if you discover an exploitable 
service. Try to find vulnerabilities BEYOND default credentials.

=== End Context ===
```

### Session Summary Generation

At session end, generate a summary either by template or by asking the LLM:

```python
def generate_session_summary(messages, findings, patches):
    # Template-based (fast, no API call):
    summary = f"Session {session_id}: Tested {n_devices} devices. "
    summary += f"Found {n_vulns} vulnerabilities. Applied {n_patches} patches. "
    summary += f"Verified {n_verified} patches. "
    summary += f"Novel tools created: {tool_names}."
    return summary
```

### Token Budget Management

The context injection must respect the model's context window. Strategy:
1. Always include: session objective + target device profiles (small)
2. Include if budget allows: recent attack history for target devices
3. Truncate: older history, non-target device details
4. Never include: full tool result JSONs from past sessions (too large)

## Files to Modify

- `core/agent.py` — add `inject_context()` method, call at session start; add `save_session()` at end
- `core/context_builder.py` (new) — builds context injection string from memory store, respects token budget
- Depends on: `01_persistent_memory.md`

## Estimated Effort

Medium. The context builder is the core logic. Token budgeting adds complexity but can start simple (character limits) and evolve.

## Implementation Notes

Executed. Files created:
- `core/context_builder.py` — `build_mission_context()` function that generates structured context from memory store (session history, device profiles, findings, patches, attack history, mode-specific instructions)
