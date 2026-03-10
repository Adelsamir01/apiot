# 05 — Event Hook System

## Problem

APIOT's agent loop is a monolithic `while True` with no extension points. There is no way to:
- Run logic before/after each tool call
- Trigger actions on session start/end
- React to specific events (vulnerability found, crash verified, patch applied)
- Add custom logging, alerting, or analytics without modifying core code

Everything is hardwired in `agent.py` and `dispatcher.py`.

## What OpenClaw Does

OpenClaw has a comprehensive hook system with 20+ lifecycle events:
- Hooks are registered per event type (e.g., `before_tool_call`, `after_tool_call`, `session_start`)
- Handlers are async functions that receive event context
- Hooks fire in registration order, errors are caught per-handler (never crash the system)
- Hooks are discovered from directories (`HOOK.md` + `handler.py`) or registered programmatically
- The `session-memory` hook auto-saves session context on reset
- The `command-logger` hook creates an audit trail

## How APIOT Should Implement This

### Event Types

```python
HOOK_EVENTS = [
    "session.start",         # Agent session begins
    "session.end",           # Agent session ends (with outcome)
    "tool.before_call",      # Before any tool is dispatched
    "tool.after_call",       # After tool returns result
    "finding.new",           # New vulnerability discovered
    "finding.patched",       # Vulnerability patched
    "finding.verified",      # Patch verified
    "phase.red_complete",    # Red team phase finished
    "phase.blue_complete",   # Blue team phase finished
    "device.first_contact",  # First time scanning a device
    "device.compromised",    # Shell or crash confirmed
    "agent.thinking",        # Agent produced reasoning
    "agent.error",           # Agent loop error
]
```

### Hook Handler Interface

```python
# core/hooks.py

from typing import Callable, Any

HookHandler = Callable[[str, dict[str, Any]], None]

class HookRegistry:
    def __init__(self):
        self._handlers: dict[str, list[HookHandler]] = {}
    
    def on(self, event: str, handler: HookHandler):
        """Register a handler for an event."""
        self._handlers.setdefault(event, []).append(handler)
    
    def emit(self, event: str, context: dict[str, Any]):
        """Fire all handlers for an event. Errors are logged, never raised."""
        for handler in self._handlers.get(event, []):
            try:
                handler(event, context)
            except Exception as e:
                logger.warning(f"Hook handler failed for {event}: {e}")

hooks = HookRegistry()
```

### Built-in Hooks

```python
# Auto-save session summary on session.end
@hooks.on("session.end")
def save_session_summary(event, ctx):
    memory = MemoryStore()
    memory.save_session(ctx["session_id"], ctx["summary"], ctx["findings"])

# Log every tool call to memory
@hooks.on("tool.after_call")
def log_tool_to_memory(event, ctx):
    memory = MemoryStore()
    memory.log_tool_call(ctx["session_id"], ctx["tool_name"], 
                         ctx["args"], ctx["result_summary"], ctx["success"])

# Update device profile on first contact
@hooks.on("device.first_contact")
def init_device_profile(event, ctx):
    memory = MemoryStore()
    memory.upsert_device_profile(ctx["ip"], ctx["firmware_id"], ctx["arch"])

# Prevent duplicate patching
@hooks.on("finding.new")
def check_existing_patches(event, ctx):
    memory = MemoryStore()
    existing = memory.get_patches_for_device(ctx["ip"])
    if any(p["attack"] == ctx["attack_name"] for p in existing):
        ctx["skip_patching"] = True  # Signal to blue phase
```

### Integration Points

The agent loop (`agent.py`) emits events at key points:

```python
# In run():
hooks.emit("session.start", {"session_id": sid, "model": self.model, ...})

# In tool dispatch:
hooks.emit("tool.before_call", {"tool_name": name, "args": args, ...})
result = dispatch_tool(name, args)
hooks.emit("tool.after_call", {"tool_name": name, "result_summary": summary, ...})

# On vulnerability:
hooks.emit("finding.new", {"ip": ip, "attack_name": tool, "details": result})

# On session end:
hooks.emit("session.end", {"session_id": sid, "outcome": "TASK_COMPLETE", ...})
```

## Files to Modify

- `core/hooks.py` (new) — hook registry and built-in handlers
- `core/agent.py` — emit events at lifecycle points
- `core/tools/dispatcher.py` — emit tool.before_call / tool.after_call
- Depends on: `01_persistent_memory.md`

## Estimated Effort

Small-medium. The hook registry is simple Python. The main work is identifying all the right emission points and building useful built-in handlers.

## Implementation Notes

Executed. Files created:
- `core/hooks.py` — `HookRegistry` class with `on()`, `off()`, `emit()`, `clear()` methods. Global `hooks` singleton. Fire-and-forget safe (errors caught per-handler).
