"""tui.py — Compact terminal status + comprehensive session log file.

Terminal shows short status lines (thinking, executing, result summary).
Full details (reasoning text, args JSON, result JSON) go to the session log only.
"""

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.text import Text

_LOGS_DIR = Path(__file__).resolve().parent.parent / "data" / "logs"

_MAX_SUMMARY = 120


def _summarize_result(result_str: str) -> str:
    """Extract a one-line summary from a JSON tool result."""
    try:
        data = json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        return result_str[:_MAX_SUMMARY]

    if isinstance(data, list):
        return f"{len(data)} item(s)"

    if isinstance(data, dict):
        if "error" in data:
            return f"error: {data['error'][:80]}"
        parts = []
        for key in ("success", "status", "verified", "exit_code", "patch_holds",
                     "applied", "recommendation", "loss_pct", "credential",
                     "attack", "targets", "ip"):
            if key in data:
                val = data[key]
                if key == "targets" and isinstance(val, list):
                    parts.append(f"{len(val)} target(s)")
                else:
                    parts.append(f"{key}={val}")
        if parts:
            return ", ".join(parts)
        return f"{len(data)} field(s)"

    return str(data)[:_MAX_SUMMARY]


class OperatorConsole:
    def __init__(self):
        self.console = Console()
        _LOGS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = _LOGS_DIR / f"session_{ts}.log"
        self._log_file = None

    def start(self):
        self._log_file = open(self.log_path, "a", encoding="utf-8")
        self._write_log(f"=== APIOT Session started at {datetime.now().isoformat()} ===\n")

    def stop(self):
        self._write_log(f"\n=== APIOT Session ended at {datetime.now().isoformat()} ===\n")
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def _write_log(self, text: str):
        if self._log_file:
            self._log_file.write(text + "\n")
            self._log_file.flush()

    def log_system(self, message: str):
        self.console.print(Text(f"  [APIOT] {message}", style="bold white"))
        self._write_log(f"[APIOT] {message}")

    def log_reasoning(self, content: str):
        self.console.print(Text("  [APIOT] Thinking...", style="dim cyan"))
        self._write_log(f"\n--- Agent Reasoning ---\n{content}\n")

    def log_tool_call(self, name: str, args: dict):
        args_short = ", ".join(f"{k}={v}" for k, v in args.items()) if args else ""
        display = f"{name}({args_short})" if args_short else name
        self.console.print(Text(f"  [APIOT] Executing: {display}", style="bold yellow"))
        args_str = json.dumps(args, indent=2)
        self._write_log(f">>> Tool Call: {name}\n    Args: {args_str}")

    def log_tool_result(self, result: str):
        summary = _summarize_result(result)
        self.console.print(Text(f"  [APIOT] Result: {summary}", style="green"))
        self._write_log(f"<<< Tool Result:\n{result}\n")

    def log_error(self, message: str):
        self.console.print(Text(f"  [ERROR] {message}", style="bold red"))
        self._write_log(f"[ERROR] {message}")

    def log_waiting(self):
        self.console.print(Text("  [APIOT] Waiting for agent response...", style="dim"))
        self._write_log("[APIOT] Waiting for agent response...")
