# 08 — Context Compaction and Token Budget Management

## Problem

APIOT appends every message and tool result to `self.messages` without limit. Long sessions will eventually exceed the model's context window and crash with an API error. There is no summarization, no compaction, and no token counting. The agent also dumps full JSON payloads into the conversation (e.g., a 6-device topology response adds ~2000 tokens every time it's called).

## What OpenClaw Does

OpenClaw's context engine has explicit token budget management:
- `assemble()` builds context under a `tokenBudget` parameter
- `compact()` summarizes older turns to reclaim tokens
- `compactionCount` tracks how many times compaction has occurred
- `totalTokens` and `totalTokensFresh` track usage per session
- The legacy engine delegates to `compactEmbeddedPiSessionDirect` which reads the JSONL transcript and produces a summary

## How APIOT Should Implement This

### Token Counting

Add a lightweight token estimator (4 chars ≈ 1 token for English):

```python
def estimate_tokens(messages: list[dict]) -> int:
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += len(content) // 4
        # Tool calls add ~50 tokens each for function name + schema
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            total += len(msg.tool_calls) * 50
    return total
```

### Compaction Strategy

When `estimate_tokens(self.messages)` exceeds 70% of the model's context window:

1. **Keep**: system prompt (always), last 4 message pairs (recent context)
2. **Summarize**: everything between system prompt and last 4 pairs
3. **Inject summary**: replace compacted messages with a single assistant message containing the summary

```python
def compact_messages(self, messages, budget):
    """Summarize older messages to fit within token budget."""
    system = messages[0]  # system prompt
    recent = messages[-8:]  # last 4 exchanges
    middle = messages[1:-8]
    
    if not middle:
        return messages
    
    # Build summary of compacted messages
    summary_parts = []
    for msg in middle:
        if msg.get("role") == "assistant" and msg.get("content"):
            summary_parts.append(f"- {msg['content'][:200]}")
        elif msg.get("role") == "tool":
            # Extract just the key outcome
            summary_parts.append(f"- Tool result: {_summarize_result(msg['content'])}")
    
    summary = "Summary of earlier actions:\n" + "\n".join(summary_parts)
    
    return [system, {"role": "assistant", "content": summary}] + recent
```

### Tool Result Truncation (in conversation history only)

Large tool results (e.g., full nmap output, topology JSON) should be truncated in the conversation history while keeping the full version in the session log:

```python
MAX_TOOL_RESULT_TOKENS = 500  # ~2000 chars

def truncate_for_history(result_json: str) -> str:
    """Keep tool result within token budget for conversation history."""
    if len(result_json) > MAX_TOOL_RESULT_TOKENS * 4:
        try:
            data = json.loads(result_json)
            # Keep structure but truncate values
            return json.dumps(_truncate_deep(data), indent=2)
        except:
            return result_json[:MAX_TOOL_RESULT_TOKENS * 4] + "\n... (truncated)"
    return result_json
```

### Model-Aware Budgets

Different models have different context windows. The budget should adapt:

```python
MODEL_CONTEXT_WINDOWS = {
    "minimax/minimax-m2.5": 128000,
    "anthropic/claude-3.5-sonnet": 200000,
    "openai/gpt-4o": 128000,
    # Default fallback
    "default": 32000,
}

def get_context_budget(model: str) -> int:
    for prefix, window in MODEL_CONTEXT_WINDOWS.items():
        if model.startswith(prefix):
            return window
    return MODEL_CONTEXT_WINDOWS["default"]
```

## Files to Modify

- `core/agent.py` — add compaction check before each API call; truncate tool results in history
- `core/compaction.py` (new) — token estimation, compaction logic, result truncation
- No dependencies on other updates (can be implemented standalone)

## Estimated Effort

Small-medium. Token estimation is trivial. The compaction logic needs care to preserve the right context. This is a critical reliability fix — without it, long sessions will crash.

## Implementation Notes

Executed. Files modified:
- `core/compaction.py` (new) — token estimation, compaction, truncation, model context windows
- `core/agent.py` — compaction check before API calls, tool result truncation in history
