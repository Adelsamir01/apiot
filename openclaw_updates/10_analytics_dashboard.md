# 10 — Analytics Dashboard and Research Metrics

## Problem

APIOT has `analytics.py` that computes PPV, TTR, and success rates, but it's never called by the agent or the CLI. There is no end-of-session report, no cross-session trend analysis, and no way to measure whether the system is improving over time. The metrics exist in code but are invisible.

## What OpenClaw Does

OpenClaw tracks token usage, session counts, and model performance across sessions. The session store maintains `inputTokens`, `outputTokens`, `totalTokens` per session. The config and session systems provide rich metadata for analytics.

## How APIOT Should Implement This

### End-of-Session Report

After every session, automatically compute and display metrics:

```
╭───────────────────────────────────────────────╮
│         APIOT Session #4 — Report             │
╰───────────────────────────────────────────────╯

  Duration:           3m 12s
  API calls:          14
  Tools executed:     11
  Tokens used:        ~24,500 (in: 18,200 / out: 6,300)

  ── Red Team ──
  Devices tested:     6
  Vulnerabilities:    5 (SSH default creds x5)
  Novel findings:     0 (all previously known)
  Exploits tried:     8
  Success rate:       62.5%
  PPV:                3.2 packets/vulnerability

  ── Blue Team ──
  Signatures:         1 (CoAP length filter)
  Patches applied:    0 (already patched in session #2)
  Patches verified:   1
  TTR:                4.2s

  ── Cross-Session Trends ──
  Sessions:           4
  Unique vulns found: 6 (total across all sessions)
  Novel vulns (new):  0 this session
  Tools created:      1 (custom_coap_fuzz, session #3)
  Coverage:           6/6 devices tested (100%)
```

### Cross-Session Analytics

Store per-session metrics in the memory database:

```sql
CREATE TABLE session_metrics (
    session_id TEXT PRIMARY KEY,
    start_time REAL,
    end_time REAL,
    duration_s REAL,
    api_calls INTEGER,
    tools_executed INTEGER,
    tokens_in INTEGER,
    tokens_out INTEGER,
    devices_tested INTEGER,
    vulns_found INTEGER,
    novel_vulns INTEGER,
    patches_applied INTEGER,
    patches_verified INTEGER,
    ppv REAL,
    ttr_s REAL,
    success_rate REAL,
    outcome TEXT
);
```

### CLI Integration

Add a `--report` flag or a report step in the CLI:

```
$ apiot --history
╭──────────────────────────────────────────────╮
│       APIOT — Session History                │
╰──────────────────────────────────────────────╯

  Session #1  2026-03-09 15:33  COMPLETE  5 vulns  1 patch  PPV=3.2
  Session #2  2026-03-09 15:47  COMPLETE  5 vulns  0 patch  PPV=2.0
  Session #3  2026-03-09 16:52  COMPLETE  6 vulns  1 patch  PPV=4.1
  Session #4  2026-03-10 09:15  COMPLETE  0 vulns  0 patch  (all known)

  Trends:
  - Novel vulnerability rate declining (system is learning)
  - PPV improving (fewer packets needed)
  - Coverage: 100% of known devices
  - 1 custom tool created and reused
```

### Export Formats

The existing `analytics.py` already supports LaTeX and CSV. Wire it up:

```python
def export_session_report(session_id, format="csv"):
    """Export session metrics for research papers."""
    if format == "csv":
        write_csv(results, path=f"data/reports/session_{session_id}.csv")
    elif format == "latex":
        table = to_latex_table(results, scenario_ids)
        Path(f"data/reports/session_{session_id}.tex").write_text(table)
```

## Files to Modify

- `core/analytics.py` — add cross-session trend computation
- `core/cli.py` — add `--history` flag and end-of-session report display
- `core/agent.py` — compute and store metrics at session end
- Depends on: `01_persistent_memory.md`

## Estimated Effort

Small. Most of the analytics code already exists. The main work is wiring it into the session lifecycle and building the CLI display.

## Implementation Notes

Executed. Files created:
- `core/analytics.py` — `Analytics` class with session_summary, cross_session_trends, device_risk_scores, tool_effectiveness_report, format_report. Calculates risk scores, patch rates, tool effectiveness from persistent memory.
