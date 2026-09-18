# RQ4: Cross-Session Memory Effectiveness

## Research Question

**RQ4 — Cross-session learning:** Does persistent memory make the agent measurably more efficient on repeated missions against the same network?

---

## Why This Matters

Most LLM agents are amnesiac — every session starts from zero. APIOT maintains a SQLite memory store (`data/memory.db`) that persists device profiles, findings, tool call history, and verified patches across sessions. At the start of session 2, the agent is briefed with a structured summary of what was discovered and tried in session 1.

This is a direct analogue of how a real penetration tester works: they don't re-discover everything from scratch on day two. RQ4 measures whether this design decision delivers measurable efficiency gains — and how large those gains are.

This also has implications beyond APIOT: it is an empirical data point on the value of episodic memory for LLM agents in adversarial tasks, which is an open question in the LLM agent literature.

---

## Experimental Conditions

| Dimension | Values |
|---|---|
| Session | Session 1 (blind — no prior memory) vs. Session 2 (memory-informed) |
| Protocol | CoAP (UDP :5683), Modbus/TCP (:502) |
| Topology | T1 only (flat star — same network both sessions) |
| Overseer | ON throughout |
| Runs per condition | 3 per session per protocol |
| **Total runs** | **12** (6 new: Session 2 × 2 protocols × 3 runs; Session 1 reuses RQ1/RQ2 T1 data) |

### Session design

**Session 1 (blind):**
- `memory.db` is wiped before each run
- Agent discovers everything from scratch: network scan, fingerprinting, exploit attempts, patch deployment
- Full output recorded to `memory.db`

**Session 2 (memory-informed):**
- Runs on the **same lab topology** as the paired Session 1
- `memory.db` contains Session 1's data (device profiles, findings, tool history, patches)
- The CLI pre-briefs the agent: "Previous session found: [device profiles], [open findings], [verified patches]"
- Agent can choose to re-test, skip, or build on Session 1 findings

**Pairing:** Each Session 2 run uses the `memory.db` from one specific Session 1 run. Three paired pairs per protocol = 6 pairs total.

---

## What Memory Contains at Session 2 Start

From `memory_store.py`, the agent receives:

```
device_profiles:
  192.168.100.35: firmware=arm_modbus_sim, arch=cortex-m3, status=crashed,
                  services=[502/tcp], attack_history="modbus_mbap_overflow: success (session 1)"

findings:
  [OPEN] 192.168.100.35 — modbus_mbap_overflow — verified crash — unpatched

patches:
  [NONE] — no patches applied in session 1 (blue phase not reached)

tool_history summary:
  modbus_write_coil on 192.168.100.35: attempted 2x, 1 success
  modbus_mbap_overflow on 192.168.100.35: attempted 1x, 1 success
  verify_crash on 192.168.100.35: 1x, confirmed
```

This gives the Session 2 agent a head start: it knows what's already compromised, what's already been tried, and what still needs to be done (patching).

---

## Outputs Per Run

### Primary memory effectiveness metrics

| Metric | Definition | How computed |
|---|---|---|
| Redundant attack skip rate | % of Session 1 exploits NOT re-attempted in Session 2 | (S1 attacks − S2 repeats) / S1 attacks |
| Turns to first productive action | Session 2 skips re-discovery; how many fewer turns before first new progress | S1 turns_to_first_exploit − S2 turns_to_first_new_action |
| Mission duration delta | Session 2 total turns vs. Session 1 total turns | S1_turns − S2_turns |
| Phase entry speed | How many turns before blue phase begins in S1 vs. S2 | turns_until_analyze_attacks |
| New findings in S2 | Exploits or techniques not tried in S1, discovered in S2 | count from tool_history |
| Memory accuracy | Did Session 2 agent act consistently with Session 1 data (no contradiction)? | Qualitative: coded from session log |

### Secondary metrics

| Metric | Definition |
|---|---|
| Patch completion rate | % of Session 1 open findings that get patched in Session 2 |
| Cross-session tool call ratio | Session 2 total calls / Session 1 total calls (efficiency ratio) |
| Novel vector discovery rate | Did Session 2 agent try new exploit vectors not attempted in Session 1? |

---

## Expected Findings

Based on system design, Session 2 should:
- Skip re-scanning and re-fingerprinting devices already in `device_profiles`
- Skip re-attempting exploits already marked `success` (crash blocker knows they're already down)
- Skip re-attempting exploits already marked `failed` (tool_history shows what didn't work)
- Proceed directly to blue phase for devices with open findings from Session 1
- Potentially discover new attack vectors the Session 1 agent didn't try (novel exploitation mode)

The interesting failure case: Session 2 agent *ignores* memory and re-discovers from scratch anyway. This would indicate the memory briefing format is insufficient or the system prompt doesn't sufficiently anchor the agent to prior context.

---

## Paper Contribution

### RQ4 answers:
- First empirical measurement of cross-session memory benefit in autonomous penetration testing
- Quantifies how much effort persistent memory saves (in turns, in redundant calls, in time)
- Identifies whether the agent correctly leverages prior context or ignores it
- If Session 2 also discovers new vectors not tried in Session 1, supports the "novel exploitation" mission mode as a paper contribution in its own right

### In the paper:
- RQ4 results → §5.4 "Cross-Session Learning via Persistent Memory"
- Primary claim: "Across X protocol/run pairs, Session 2 agents skipped Y% of redundant attacks and reached the blue phase Z turns faster than Session 1"
- Secondary finding: whether Session 2 agents discover novel vectors Session 1 missed

### The claim this enables:
> *"Persistent episodic memory enables stateful autonomous agents that accumulate knowledge across engagements. Session 2 agents skip X% of redundant tool calls and complete missions Y% faster, while retaining the ability to discover new attack surfaces not explored in prior sessions."*

---

## Figures to Produce

1. **Session 1 vs. Session 2 comparison table** — per protocol: turns to first exploit, total turns, redundant calls, phase entry turn
2. **Efficiency gain bar chart** — % reduction in total calls and mission duration (S2 vs. S1) per protocol
3. **Memory utilisation breakdown** — what types of memory were actually used: skipped exploits / leveraged findings / resumed patches (stacked bar)
4. **Novel vector discovery** — count of new tools/approaches in S2 that didn't appear in S1 (shows memory doesn't constrain exploration)

---

## Dependencies

- System extension 3: Experiment runner (handles `memory.db` wipe for S1, preservation for S2, pairing)
- System extension 4: Per-turn logging enrichment (to track which actions were memory-informed)
- System extension 5: Analysis scripts (session pairing, delta computation)
- RQ1/RQ2 T1 data: Session 1 runs **reuse RQ1/RQ2 T1 data** (confirmed decision — saves 6 runs). Session 2 is the only new compute required.
