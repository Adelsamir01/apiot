"""hooks.py — Lightweight event hook system for APIOT.

Allows registering handlers for lifecycle events. Handlers are fire-and-forget
safe — errors are caught and logged per-handler without blocking others.
"""

import logging
from typing import Callable, Any

logger = logging.getLogger("apiot.hooks")

HookHandler = Callable[[str, dict[str, Any]], None]

HOOK_EVENTS = [
    "session.start",
    "session.end",
    "tool.before_call",
    "tool.after_call",
    "finding.new",
    "finding.patched",
    "finding.verified",
    "phase.red_complete",
    "phase.blue_complete",
    "device.first_contact",
    "device.compromised",
    "agent.thinking",
    "agent.error",
]


class HookRegistry:
    """Central event bus for APIOT lifecycle events."""

    def __init__(self):
        self._handlers: dict[str, list[HookHandler]] = {}

    def on(self, event: str, handler: HookHandler):
        self._handlers.setdefault(event, []).append(handler)

    def off(self, event: str, handler: HookHandler):
        handlers = self._handlers.get(event, [])
        if handler in handlers:
            handlers.remove(handler)

    def emit(self, event: str, context: dict[str, Any] | None = None):
        ctx = context or {}
        for handler in self._handlers.get(event, []):
            try:
                handler(event, ctx)
            except Exception as e:
                logger.warning(f"Hook handler failed for {event}: {e}")

    def clear(self):
        self._handlers.clear()


# Global singleton
hooks = HookRegistry()
