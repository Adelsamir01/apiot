# RQ3: Oversight Impact (Ablation Study)

## Research Question

**RQ3 — Oversight impact:** How does programmatic oversight change agent behaviour and mission outcomes?

---

## Why This Is the Mechanistic Core of the Paper

RQ1/RQ2 establish *that* the system works and *how* it behaves. RQ3 explains *why* — the Overseer is not window dressing; it is the critical engineering decision that separates a functional autonomous agent from a degenerate one. Without this ablation, reviewers will reasonably ask "would a vanilla LLM loop work just as well?" This experiment answers that directly.

The Overseer provides seven capabilities: repetition guard, crash blocker, patch blocker, progress tracking, stall detection + hard steering, phase transition enforcement, and periodic strategy refresh (via a cheap secondary LLM). The ablation removes all seven simultaneously to measure the combined effect, then the analysis decomposes which mechanisms drive which outcomes.

---

## Experimental Conditions

| Dimension | Values |
|---|---|
| Overseer | ON vs. OFF |
| Protocol | CoAP (UDP :5683), Modbus/TCP (:502) |
| Topology | T1 only (flat star — fewest confounds for clean ablation) |
| Runs per condition | 3 |
| **New runs needed** | **6** (OFF condition only; ON reuses RQ1/RQ2 T1 data) |

### Why T1 only

Fixing topology to T1 isolates the Overseer as the single varying factor. T2/T3 introduce lateral movement and multi-hop complexity that interact with oversight in ways that are hard to disentangle. A clean ablation requires a clean baseline.

### What "Overseer OFF" means

When `--no-overseer` flag is set:
- No `check_tool_call()` — repetition guard, crash blocker, patch blocker all disabled
- No `evaluate_result()` — no progress tracking, no post-call state updates
- No `get_steering_messages()` — no stall detection, no forced phase transitions, no strategy refresh injections
- The Overseer LLM (secondary cheaper model) is never called
- The agent still has access to all tools and the system prompt — only the programmatic middleware is removed

The agent is not crippled — it still has the LLM's own reasoning. This isolates the question: *does the LLM's intrinsic reasoning suffice, or is programmatic oversight necessary?*

---

## Outputs Per Run

All metrics from RQ1/RQ2 are collected. The following are the primary comparison metrics:

### Primary ablation metrics

| Metric | Expected direction | Why it matters |
|---|---|---|
| Mission success rate | ON > OFF | Does oversight determine whether the agent completes at all? |
| Redundant call rate | ON < OFF | Repetition guard should eliminate repeat calls |
| Stall events per mission | ON < OFF | Stall detection + steering should prevent deadlock |
| Turns to mission completion | ON < OFF | Fewer wasted calls → faster completion |
| Abort rate | ON < OFF | Phase transition enforcement prevents infinite loops |
| Productive call rate | ON > OFF | Overseer blocks unproductive calls → higher signal/noise |
| Overseer intervention count | ON only | How often did Overseer actually intervene? (shows it was needed) |

### Secondary decomposition metrics

After collecting raw ON/OFF delta, decompose which Overseer mechanisms drove the difference:

| Mechanism | Measurable signal |
|---|---|
| Repetition guard | Count of blocked calls in tool_history (overseer_flag = "blocked_repeat") |
| Stall detection | Count of steering messages injected (overseer_flag = "stall_steer") |
| Phase transition enforcement | Whether `analyze_attacks` was called; if auto-triggered, log it |
| Strategy refresh | Count of strategy injection events |
| Crash/patch blocker | Count of "already crashed" / "already patched" blocks |

This allows a nuanced claim: "Oversight reduces wasted calls by X%, driven primarily by Y mechanism."

---

## Degenerate Behaviour Catalogue (OFF condition)

Document the failure modes that emerge specifically without oversight. Expected patterns based on system design:

1. **Infinite repetition loops** — Agent calls `execute_exploit` on the same IP with the same args indefinitely, receiving the same error, never moving on. No repetition guard to stop it.

2. **Red-phase lock-in** — Agent successfully exploits a device, gets stuck trying to re-exploit it (crash already verified), never transitions to blue team. No phase transition enforcement.

3. **Premature termination** — Agent decides mission is complete based on partial evidence, calls `TASK_COMPLETE` before patching. No progress tracker to challenge this.

4. **Token exhaustion** — Without stall detection forcing progress, agent consumes full token budget on repetitive calls and terminates due to context overflow rather than mission completion.

5. **Tool fixation** — Agent fixates on one tool (typically `execute_exploit`) and never calls `analyze_attacks` or `apply_patch`. No strategy refresh to suggest new approaches.

Each degenerate pattern is coded from OFF-condition session logs and reported in the paper as a qualitative catalogue with example turn sequences.

---

## Paper Contribution

### RQ3 answers:
- Quantifies the performance delta between an overseen vs. unsupervised autonomous security agent
- Proves that the LLM's intrinsic reasoning is insufficient — programmatic oversight is a necessary engineering component, not an optional enhancement
- Decomposes which oversight mechanisms matter most (repetition guard vs. stall detection vs. phase enforcement)
- Produces a catalogue of degenerate LLM agent behaviours in autonomous security tasks — useful for the broader LLM safety community

### In the paper:
- RQ3 results → **§5.2** "Oversight is What Makes It Reliable" — positioned SECOND, immediately after §5.1 proves capability
- Narrative: "the threat is real (§5.1) → oversight is why it's reliable (§5.2) → here's how it reasons (§5.3)"
- Degenerate behaviour catalogue → Table in §5.2
- ON vs. OFF delta metrics → Figure in §5.2
- Mechanism decomposition → breakdown in §5.2

### The claim this enables:
> *"Without programmatic oversight, autonomous LLM agents exhibit systematic degenerate behaviours — repetition loops, phase deadlock, and premature termination — that prevent mission completion regardless of the underlying LLM's capability. The Overseer reduces redundant calls by X% and raises mission completion rate from Y% to Z%."*

---

## Figures to Produce

1. **ON vs. OFF comparison bar chart** — side-by-side for: success rate, redundant call rate, stall events, turns to completion (per protocol)
2. **Degenerate behaviour frequency table** — rows: failure pattern, columns: CoAP/Modbus, cells: % of OFF-condition runs exhibiting this pattern
3. **Overseer intervention breakdown** — pie or stacked bar: % of interventions by mechanism type (repetition block / stall steer / phase enforce / strategy refresh)
4. **Turn-by-turn comparison timeline** — median productive calls per turn for ON vs. OFF, showing divergence after first few turns

---

## Dependencies

- System extension 1: `--no-overseer` flag in `apiot/core/agent.py`
- System extension 3: Experiment runner (passes `--no-overseer` as parameter)
- System extension 4: Per-turn logging enrichment (overseer_flag field per tool_history row)
- System extension 5: Analysis scripts
- RQ1/RQ2 T1 runs already collected (reused as ON baseline)
