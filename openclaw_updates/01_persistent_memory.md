# 01 — Persistent Memory System

## Problem

APIOT has no memory across sessions. Every time the agent starts, it begins from scratch — it doesn't know what vulnerabilities it found before, what patches it applied, what attacks failed, or what devices it already fully tested. The current `network_state.json` and `attack_log.json` are flat files with no retrieval intelligence. The agent brute-forces the same `root:root` credentials every run because it has no recollection.

## What OpenClaw Does

OpenClaw uses a **hybrid retrieval-augmented memory** built on SQLite with vector embeddings:

- **Memory files** (`MEMORY.md`, `memory/*.md`) — persistent knowledge the agent always has access to (semantic/procedural memory).
- **Session transcripts** (JSONL) — every past conversation is indexed and searchable (episodic memory).
- **Embedding-based search** — queries are embedded and matched against stored chunks via cosine similarity.
- **Full-text search (FTS5/BM25)** — keyword fallback when embeddings aren't available.
- **Temporal decay** — older memories score lower, but "evergreen" knowledge files are exempt.
- **MMR re-ranking** — Maximal Marginal Relevance prevents returning redundant memories.
- **Content-hash deduplication** — identical content is never re-indexed.

## How APIOT Should Implement This

### Data Model

Create `data/memory.db` (SQLite) with these tables:

```
sessions       — id, start_time, end_time, model, summary, outcome (COMPLETE/ABORTED)
findings       — id, session_id, ip, device_name, finding_type (vuln/credential/crash/patch), 
                 tool_used, details_json, status (open/patched/verified), created_at
tool_history   — id, session_id, ip, tool_name, args_json, result_summary, success, created_at
patches        — id, finding_id, rule, signature_json, applied_at, verified, verified_at
device_profile — ip, firmware_id, arch, first_seen, last_seen, known_creds, services_json,
                 attack_history_summary
```

### Key Behaviors

1. **Session start**: Load the latest `device_profile` for every known device. Inject a "network history" summary into the system prompt showing what's been done before.
2. **During session**: Every tool call result is logged to `tool_history`. Every vulnerability is logged to `findings`. Every patch to `patches`.
3. **Session end**: Generate a session summary (LLM-generated or template-based) and store in `sessions`. Update `device_profile` with new findings.
4. **Next session**: Before the agent begins, query `findings` for open vulnerabilities, `patches` for active patches, and `device_profile` for known credentials/services. Inject this as context.

### What This Enables

- Agent sees: "Device 192.168.100.10 has been tested in 3 prior sessions. Known creds: root:root (SSH). CoAP overflow attempted 2x, failed. Last patched: iptables rule for CoAP length filter, verified."
- Agent skips re-bruting known creds and focuses on novel attack vectors.
- Agent knows which patches exist and doesn't re-apply them.

## Files to Modify

- `core/memory_store.py` (new) — SQLite-backed memory store with the schema above
- `core/agent.py` — inject memory context into system prompt at session start; write session summary at end
- `core/tools/dispatcher.py` — log every tool call to `tool_history`
- `core/agent_loop.py` — log findings and patches to the memory store

## Estimated Effort

Medium-large. The SQLite schema and read/write logic is straightforward. The main complexity is in generating useful summaries and injecting them into the prompt without exceeding context limits.

## Implementation Notes

Executed. Files created:
- `core/memory_store.py` — SQLite-backed persistent memory with tables: sessions, findings, tool_history, patches, device_profiles
