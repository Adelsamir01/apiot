"""compaction.py — Context compaction and token budget management for APIOT.

Provides lightweight token estimation, conversation compaction when context
exceeds budget, and tool-result truncation for conversation history.
"""

import json


def _get(msg, key: str, default=""):
    """Extract a field from a message that may be a dict or Pydantic object."""
    if isinstance(msg, dict):
        return msg.get(key, default)
    return getattr(msg, key, default)


MODEL_CONTEXT_WINDOWS = {
    "minimax/": 128_000,
    "anthropic/claude": 200_000,
    "openai/gpt-4o": 128_000,
    "google/gemini": 1_000_000,
    "meta-llama/": 128_000,
}
_DEFAULT_CONTEXT_WINDOW = 32_000


def estimate_tokens(messages: list) -> int:
    """Estimate token count for a message list (4 chars ≈ 1 token)."""
    total = 0
    for msg in messages:
        content = _get(msg, "content", "") or ""
        if isinstance(content, str):
            total += len(content) // 4
        tc = _get(msg, "tool_calls", None)
        if tc:
            total += len(tc) * 50
    return total


def truncate_result_for_history(result_json: str, max_chars: int = 2000) -> str:
    """Truncate large tool results for conversation history.

    Tries to preserve JSON structure with truncated values; falls back
    to plain string truncation.
    """
    if len(result_json) <= max_chars:
        return result_json

    try:
        data = json.loads(result_json)
        truncated = _truncate_value(data, max_chars)
        return json.dumps(truncated, indent=2)
    except (json.JSONDecodeError, TypeError):
        return result_json[:max_chars] + "\n... (truncated)"


def _truncate_value(obj, budget: int, depth: int = 0):
    """Recursively truncate a parsed JSON value to fit within *budget* chars."""
    if depth > 6:
        return "..."
    if isinstance(obj, str):
        if len(obj) > 200:
            return obj[:200] + "..."
        return obj
    if isinstance(obj, list):
        out = []
        for item in obj[:10]:
            out.append(_truncate_value(item, budget, depth + 1))
        if len(obj) > 10:
            out.append(f"... ({len(obj) - 10} more items)")
        return out
    if isinstance(obj, dict):
        out = {}
        for k, v in list(obj.items())[:15]:
            out[k] = _truncate_value(v, budget, depth + 1)
        if len(obj) > 15:
            out["..."] = f"({len(obj) - 15} more keys)"
        return out
    return obj


def compact_messages(messages: list, budget_tokens: int) -> list:
    """Summarize older messages when conversation exceeds token budget.

    Keeps the system prompt (first message) and the last 8 messages,
    replacing everything in between with a bullet-point summary.
    """
    if len(messages) <= 10:
        return messages

    system = messages[0]
    recent = messages[-8:]
    middle = messages[1:-8]

    if not middle:
        return messages

    summary_parts = []
    for msg in middle:
        role = _get(msg, "role", "")
        content = _get(msg, "content", None)

        if role == "assistant" and content:
            summary_parts.append(f"- [assistant] {str(content)[:200]}")
        elif role == "tool" and content:
            summary_parts.append(f"- [tool result] {_summarize_result(str(content))}")
        elif role == "user" and content:
            summary_parts.append(f"- [user] {str(content)[:150]}")

    summary_text = (
        "**Context compacted.** Summary of earlier actions:\n"
        + "\n".join(summary_parts)
    )

    if len(summary_text) // 4 > budget_tokens * 0.25:
        summary_text = summary_text[: budget_tokens] + "\n... (summary truncated)"

    return [system, {"role": "assistant", "content": summary_text}] + recent


def _summarize_result(content: str) -> str:
    """Extract a short summary string from a tool result."""
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            status = data.get("status", "")
            keys = list(data.keys())[:5]
            return f"status={status}, keys={keys}"
        if isinstance(data, list):
            return f"list with {len(data)} items"
    except (json.JSONDecodeError, TypeError):
        pass
    return content[:120] + ("..." if len(content) > 120 else "")


def get_context_budget(model: str) -> int:
    """Look up context window size for a model name."""
    for prefix, window in MODEL_CONTEXT_WINDOWS.items():
        if model.startswith(prefix):
            return window
    return _DEFAULT_CONTEXT_WINDOW
