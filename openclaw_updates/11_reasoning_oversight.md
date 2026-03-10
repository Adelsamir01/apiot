# 11 — Reasoning Oversight Layer ("The Brain")

## The Problem

APIOT's agent loop is a **dumb relay**: `LLM → tool → result → LLM`. There is no programmatic layer between "tool result received" and "next LLM call" that evaluates progress, detects stalls, triggers pivots, refreshes strategy, or enforces phase transitions. Every reasoning decision is offloaded entirely to the LLM's next completion, with zero guardrails.

Concrete symptoms:
- The agent can brute-force the same credentials 10 times and nothing stops it.
- If an exploit fails, no code evaluates whether to retry, try a different approach, or move on.
- `strategy.py`, `tool_tracker.py`, `context_builder.py` are called ONCE at session start and never again.
- The `_check_success` result is stored in SQLite but never read back during the loop.
- Phase transitions (red → blue) exist only in the LLM's head — no programmatic enforcement.
- `ToolTracker.recommend_tools()` is completely dead code — nothing calls it.
- There is no stall detection, no repetition guard, no progress tracking.

## How OpenClaw Solves This

OpenClaw does **not** use a separate "supervisor agent." Instead it uses a **hook-driven middleware pipeline** that intercepts every stage of the LLM loop:

1. **`transformContext()`** — Runs before EVERY LLM call. Prunes, injects, and modifies messages. This is the primary oversight mechanism.
2. **Tool Loop Detection** — Sliding-window hash of `(tool_name, args)`. Detects:
   - `generic_repeat`: same call 10+ times → block
   - `ping_pong`: A→B→A→B alternating pattern → block
   - `global_circuit_breaker`: 30+ tool calls total → force stop
3. **`tool_call` interception** — Hooks can **block** a tool call before execution and return a synthetic result explaining why.
4. **`tool_result` interception** — Hooks can **modify** a tool result before the LLM sees it (enrich, annotate, replace).
5. **Compaction Safeguards** — When context is compacted, tool failures and "red lines" are preserved in the summary so the LLM doesn't forget what failed.
6. **Steering** — Mid-run interruption: inject a redirect message between tool calls to force the agent to change course.

Key insight: The LLM is still the "brain," but it operates within **structured guardrails** that prevent degenerate behavior and ensure it has current, relevant context at every step.

## Proposed Architecture for APIOT

### New file: `core/oversight.py`

A single class `Overseer` that sits inside the agent loop between tool execution and the next LLM call. It is NOT a separate LLM — it is deterministic Python logic that uses the data already in `MemoryStore`, `ToolTracker`, and `strategy.py`.

```
Current loop:
  LLM call → dispatch tools → append results → LLM call

New loop:
  LLM call → dispatch tools → OVERSEER evaluates → inject guidance → LLM call
```

### Overseer Responsibilities

#### 1. Repetition Guard (tool loop detection)
- Maintain a sliding window of the last 20 `(tool_name, ip, key_args_hash)` tuples.
- If the same tuple appears 3+ times: **block** the call, return a synthetic result: `"BLOCKED: You have already tried {tool} on {ip} {n} times. Try a different approach."`
- If any tool+IP combo fails 3+ times: inject a user message suggesting `create_tool` or `run_command` for manual probing.

#### 2. Stall Detection
- Track `last_finding_turn` — the loop iteration where a vuln/shell/patch was last confirmed.
- If `current_turn - last_finding_turn > STALL_THRESHOLD` (e.g., 8 turns): inject a steering message:
  `"You have not made progress in {n} turns. Review your approach. Consider: {untried_attacks from strategy.py}"`
- If stall continues for another 5 turns: force phase transition or TASK_COMPLETE.

#### 3. Mid-Loop Strategy Refresh
- Every N tool calls (e.g., every 5), call `strategy.build_attack_plan()` and `tool_tracker.build_tool_context()` for active targets.
- Inject the refreshed strategy as a user message: `"[OVERSEER] Updated situation: {context}"`
- This replaces the stale session-start-only injection.

#### 4. Phase Transition Enforcement
- Track which targets have been attempted (from `MemoryStore.get_tool_history_for_device`).
- Track which targets are in the topology.
- When `attempted_targets >= total_targets` OR `consecutive_failures > threshold`: emit `phase.red_complete` hook, inject: `"[OVERSEER] Red team phase complete. {vuln_count} vulnerabilities found. Begin blue team phase now."`
- Similarly detect when blue phase is done: all findings patched + verified → emit `phase.blue_complete`.

#### 5. Tool Call Interception (pre-dispatch)
- Before dispatching a tool call, check:
  - Is this a duplicate of a recent call? → Block with explanation.
  - Is this target already crashed? → Block with `"Target {ip} is already crashed. Move to next target."`
  - Is this attack already patched (verified)? → Block with `"Attack {name} on {ip} already has a verified patch."`
  - Has this tool failed N times globally? → Warn with low-effectiveness data from ToolTracker.

#### 6. Tool Result Enrichment (post-dispatch)
- After a tool returns, before appending to messages:
  - If `_check_success(result)` is True: update device profile via `DeviceFingerprinter`, log finding to MemoryStore, update progress counters.
  - If False and attempt_count >= 2: append a hint from `strategy.get_untried_attacks()` to the result string.
  - Always: append a one-line progress summary: `"[Progress: {vuln_count} vulns, {patch_count} patches, {attempted}/{total} targets]"`

#### 7. Progress Dashboard (injected context)
- Every 5 turns, inject a compact progress summary as a user message:
  ```
  [OVERSEER STATUS]
  Turn: 15/max_100
  Targets: 4/6 attempted, 2 compromised
  Findings: 3 open, 1 patched (0 verified)
  Stall: 0 turns since last finding
  Recommendation: Try coap_option_overflow on 192.168.200.10
  ```

### How it integrates into `agent.py`

```python
# In __init__:
self.overseer = Overseer(self.memory, self.model)

# In the loop, BEFORE dispatching a tool call:
blocked, reason = self.overseer.check_tool_call(fn_name, fn_args)
if blocked:
    result_json = json.dumps({"blocked": True, "reason": reason})
    # skip dispatch, just give the LLM the blocked result
else:
    result_json = dispatch_tool(fn_name, fn_args)

# AFTER dispatching, before appending to messages:
enriched = self.overseer.evaluate_result(fn_name, fn_args, result_json)
# enriched may have progress hints appended

# AFTER all tool calls in this turn, before next LLM call:
steering = self.overseer.get_steering_messages()
for msg in steering:
    self.messages.append(msg)
    console.log_system(f"[OVERSEER] {msg['content'][:100]}")
```

### Overseer Internal State

```python
class Overseer:
    def __init__(self, memory, model):
        self.memory = memory
        self.tracker = ToolTracker(memory)
        self.fingerprinter = DeviceFingerprinter(memory)
        self.turn = 0
        self.last_finding_turn = 0
        self.call_window: list[tuple[str, str, str]] = []  # (tool, ip, args_hash)
        self.targets_attempted: set[str] = set()
        self.targets_total: int = 0
        self.phase = "red"  # "red" | "blue" | "done"
        self.vuln_count = 0
        self.patch_count = 0
        self.verified_count = 0
```

## Files to Create / Modify

| File | Action | Description |
|------|--------|-------------|
| `core/oversight.py` | **CREATE** | The `Overseer` class — all oversight logic in one place |
| `core/agent.py` | **MODIFY** | Wire overseer into the loop: pre-dispatch check, post-dispatch evaluate, inter-turn steering |
| `core/hooks.py` | **MODIFY** | Make `emit()` return a list of handler results so hooks can block/modify |

## Dependencies

- `core/memory_store.py` (reads tool history, findings, patches, device profiles)
- `core/tool_tracker.py` (tool effectiveness, recommendations)
- `core/strategy.py` (untried attacks, attack plans)
- `core/fingerprint.py` (device profile updates)
- `core/hooks.py` (phase transition events)

## Estimated Effort

Medium-large. The Overseer class itself is ~200 lines of deterministic Python. The main complexity is wiring it cleanly into the agent loop without breaking the existing flow. No new LLM calls needed — this is pure programmatic logic using data that already exists.

## Key Design Decisions

1. **Not a second LLM call.** The overseer is deterministic Python. Using an LLM for oversight would double API costs and add latency. OpenClaw also does not use a separate LLM for oversight — its guardrails are all code.

2. **Steering via user messages.** When the overseer needs to redirect the agent, it injects a `{"role": "user", "content": "[OVERSEER] ..."}` message. The LLM treats this as authoritative instruction. This matches OpenClaw's `steer()` pattern.

3. **Blocking via synthetic results.** When a tool call is blocked, the overseer returns a fake tool result explaining why. The LLM sees this as a normal tool response and adapts. This matches OpenClaw's `tool_call` hook returning `{ block: true, reason }`.

4. **Idempotent and stateless between sessions.** The Overseer resets each session. Cross-session intelligence comes from MemoryStore (which persists).

## Execution Order

This should be implemented as a single atomic change:
1. Create `core/oversight.py` with the `Overseer` class
2. Modify `core/agent.py` to instantiate and use the Overseer
3. Test with a live agent run to verify steering messages appear and repetition is blocked

## Implementation Notes

Executed. Files created/modified:
- `core/oversight.py` (new) — `Overseer` class with 7 capabilities:
  1. Repetition guard (sliding window, blocks after 3 identical calls)
  2. Crashed-target blocker
  3. Patched-attack blocker
  4. Progress tracking (vulns, patches, targets attempted/compromised)
  5. Stall detection (steering after 8 turns without progress, hard limit at 15)
  6. Phase transition enforcement (auto-triggers blue team when all targets attempted)
  7. Strategy refresh every 5 turns (re-queries tool_tracker + strategy engine)
  8. Circuit breaker at 120 turns
  9. Failure hints (suggests untried vectors after 2+ fails on same target)
- `core/agent.py` — Wired Overseer into main loop:
  - Pre-dispatch: `check_tool_call()` blocks degenerate calls
  - Post-dispatch: `evaluate_result()` enriches results with progress line and hints
  - Inter-turn: `get_steering_messages()` injects oversight guidance
  - Auto-detects target count from `get_actionable_targets` results
- `tests/test_oversight.py` (new) — 39 unit tests covering all capabilities
- Verified live with real LLM: overseer blocked repetitive brute_force_ssh calls and injected strategy refresh
