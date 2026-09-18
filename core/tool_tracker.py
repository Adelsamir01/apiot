"""tool_tracker.py — Adaptive tool selection with effectiveness tracking.

Tracks tool usage statistics and success rates per device category.
Recommends tools based on historical effectiveness and ranks them.
"""

import json
from pathlib import Path
from apiot.core.memory_store import MemoryStore


class ToolTracker:
    """Tracks tool effectiveness and recommends optimal tool ordering."""

    def __init__(self, memory: MemoryStore):
        self.memory = memory

    def get_tool_stats(self, ip: str | None = None) -> dict[str, dict]:
        """Get aggregated success/fail counts per tool.

        Args:
            ip: Optional IP to scope stats. None = global.

        Returns:
            Dict of tool_name -> {calls, successes, rate}.
        """
        if ip:
            history = self.memory.get_tool_history_for_device(ip, limit=500)
        else:
            rows = self.memory._conn.execute(
                "SELECT tool_name, success FROM tool_history"
            ).fetchall()
            history = [{"tool_name": r["tool_name"], "success": r["success"]} for r in rows]

        stats: dict[str, dict] = {}
        for h in history:
            name = h.get("tool_name", "unknown")
            if name not in stats:
                stats[name] = {"calls": 0, "successes": 0, "rate": 0.0}
            stats[name]["calls"] += 1
            if h.get("success"):
                stats[name]["successes"] += 1

        for s in stats.values():
            s["rate"] = s["successes"] / s["calls"] if s["calls"] > 0 else 0.0

        return stats

    def rank_tools(self, ip: str | None = None) -> list[tuple[str, float]]:
        """Rank tools by success rate (descending).

        Returns:
            List of (tool_name, success_rate) tuples.
        """
        stats = self.get_tool_stats(ip)
        ranked = [(name, s["rate"]) for name, s in stats.items()]
        ranked.sort(key=lambda x: (-x[1], -stats[x[0]]["calls"]))
        return ranked

    def recommend_tools(self, ip: str, available_tools: list[str],
                        top_n: int = 5) -> list[str]:
        """Recommend tools for a target based on past effectiveness.

        Tools that have never been tried are boosted to encourage exploration.

        Args:
            ip: Target IP.
            available_tools: List of available tool names.
            top_n: Number of recommendations.

        Returns:
            Ordered list of recommended tool names.
        """
        stats = self.get_tool_stats(ip)

        scored: list[tuple[str, float]] = []
        for tool in available_tools:
            if tool in stats:
                s = stats[tool]
                score = s["rate"] * 0.7 + (1.0 / max(s["calls"], 1)) * 0.3
            else:
                score = 0.8  # exploration bonus for untried tools
            scored.append((tool, score))

        scored.sort(key=lambda x: -x[1])
        return [name for name, _ in scored[:top_n]]

    def build_tool_context(self, ip: str | None = None) -> str:
        """Build a context string summarizing tool effectiveness."""
        stats = self.get_tool_stats(ip)
        if not stats:
            return "No tool usage history yet."

        lines = ["Tool effectiveness:"]
        ranked = self.rank_tools(ip)
        for name, rate in ranked[:10]:
            s = stats[name]
            lines.append(f"  {name}: {s['successes']}/{s['calls']} ({rate:.0%})")
        return "\n".join(lines)
