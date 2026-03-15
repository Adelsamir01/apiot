# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**APIOT** (Agentic Purple IoT Toolkit) is a fully autonomous LLM-driven Red/Blue (Purple) team agent orchestrator for IoT security testing. The agent follows a continuous `THOUGHT → ACTION → OBSERVATION` loop using Claude (via OpenRouter) as the reasoning engine, with Python toolkit functions as its tools.

**Key constraint**: APIOT never controls the lifecycle of `iot_vlab` (the external IoT lab). It only communicates via read-only REST API and sends raw network packets. The lab is always externally managed.

## Commands

### Installation
```bash
pip3 install -e .
```
Python 3.10+ required. Many exploits require `sudo`.

### Run the agent
```bash
apiot                          # Interactive onboarding (recommended)
sudo python3 -m apiot.core.agent          # Direct launch with TUI
sudo python3 -m apiot.core.agent --no-tui # Raw stdout
```

### Manual tool harness (test individual tools without the LLM loop)
```bash
sudo python3 -m apiot.core.agent_loop get_state
sudo python3 -m apiot.core.agent_loop get_targets
sudo python3 -m apiot.core.agent_loop verify_crash 192.168.100.35
```

### Network mapping
```bash
sudo python3 -m apiot.core.mapper
```

### Tests
```bash
python3 -m pytest tests/test_isolation.py -v     # Verify lab isolation (no lifecycle control)
python3 -m pytest tests/test_guardrails.py -v    # Config + infrastructure checks
python3 -m pytest tests/test_oversight.py -v     # Oversight system validation
python3 -m pytest tests/test_openclaw_updates.py -v  # Memory system tests
python3 -m pytest tests/ -v                      # All tests
```
Tests requiring a live `iot_vlab`: `tests/full_autonomous_run.py`, `tests/closed_loop_remediation.py`, `tests/test_phase1.py`.

## Architecture

### Core Agent Loop (`core/agent.py`)
The `APIOTAgent` class drives the entire system. It:
1. Builds an OpenAI-compatible client pointed at OpenRouter
2. Maintains the full conversation history with the LLM
3. Submits all tool schemas from `core/tools/registry.py`
4. Dispatches tool calls via `core/tools/dispatcher.py`
5. Manages context compaction (`core/compaction.py`) when approaching token limits
6. Coordinates an independent Overseer LLM (`core/oversight.py`) that monitors for stalled/repetitive behavior and injects strategic directives

### Tool System (`core/tools/`)
- **`registry.py`**: OpenAI-compatible JSON Schema definitions for all 19 agent-callable tools
- **`dispatcher.py`**: Routes LLM tool calls (by name + args) to actual Python implementations in `core/agent_loop.py` and the toolkit

### Two-Phase Purple Team Workflow (EXT7: Protocol Primitives)
**Phase 1 — Red Team:**
- `get_actionable_targets` → classify by open ports
- **Bare-Metal OT** (port 502 Modbus): `modbus_request(function_code, data_hex, claimed_length)` — agent reasons about MBAP overflow
- **Bare-Metal OT** (port 5683 CoAP): `coap_send(options_hex, ...)` — agent reasons about option delta/length encoding
- **Raw probing**: `tcp_send`, `udp_send` for any other protocol
- Always call `verify_crash` or `verify_shell` after each probe

**Phase 2 — Blue Team:**
- Agent reasons about what byte pattern makes the exploit unique
- `iptables_rule(match_type, match_value, protocol, dport)` — agent crafts the filter
- `modbus_fc_filter(function_code)` — block specific Modbus FC
- `coap_rate_limit(rate, burst)` — rate-limit CoAP floods
- `verify_patch(target_ip, protocol, port, payload_hex)` — replay exact bytes, confirm device survives

### New Toolkit Files (EXT7)
- **`toolkit/protocol_tools.py`**: `coap_send`, `modbus_request`, `tcp_send`, `udp_send`
- **`toolkit/defense_primitives.py`**: `iptables_rule`, `protocol_block`, `modbus_fc_filter`, `coap_rate_limit`

### Persistence Layer
- `data/network_state.json`: Discovered hosts, fingerprints, active vulnerabilities
- `data/attack_log.json`: Append-only exploit execution log
- `data/remediation_log.json`: Blue team patch records
- `data/memory.db`: SQLite store with FTS5 and vector embeddings for cross-session semantic memory (`core/memory_store.py`)
- `data/logs/session_*.log`: Per-session detailed TUI output

### Lab Bridge (`core/lab_bridge.py`)
Pre-flight sequence run before the agent loop:
1. Check `iot_vlab` REST API is reachable
2. Confirm at least one device is ready
3. Run `core/mapper.py` to populate `network_state.json`

### Configuration
Runtime config in `.env` (never committed):
```
OPENROUTER_API_KEY=...   # Required
LLM_MODEL=...            # Defaults to Claude 3.5 Sonnet; any OpenRouter model works
```

## Key Design Patterns

- **Tool schemas are the interface**: The LLM only sees JSON Schema definitions in `registry.py`. Changing tool behavior without updating the schema breaks the agent.
- **Dispatcher is the contract**: `dispatcher.py` maps schema names to Python callables. New tools need entries in both files.
- **`agent_loop.py` is the glue**: The `cmd_*` functions in `agent_loop.py` are the actual implementations that dispatcher routes to. They bridge high-level tool calls to low-level toolkit functions.
- **Oversight is a separate LLM call**: The Overseer runs on a cheaper model and evaluates agent progress every N turns. Its directives are injected as system messages into the main conversation.
- **Context compaction is automatic**: When token count nears the model limit, `compaction.py` summarizes older messages in-place. Tool results are truncated to a configurable max length.
