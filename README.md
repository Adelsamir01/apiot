# APIOT — Agentic Purple IoT Toolkit

APIOT is a **fully autonomous, LLM-driven Red/Blue agent orchestrator** for IoT security testing. It uses a continuous `THOUGHT → ACTION → OBSERVATION` loop to autonomously scan, attack, verify vulnerabilities, and then apply and verify defenses — all without human guidance.

The LLM (via OpenRouter) acts as the reasoning brain. APIOT provides the protocol primitives, network mapping, and session memory. It targets a virtualized IoT network provided by **iot_vlab**.

---

## Relationship to iot_vlab

APIOT is built as a **client of [iot_vlab](https://github.com/Adelsamir01/iot_vlab)**. The two systems run side-by-side:

```
iot_vlab                              APIOT
─────────────────────────────────     ──────────────────────────────────
Emulates IoT devices in QEMU          Autonomously attacks those devices
Bridges them to 192.168.100.0/24  ←── Scans, fingerprints, exploits
Exposes REST API on :5000             Queries /topology, /library, /ready
Manages device lifecycle              NEVER touches device lifecycle
```

**APIOT has zero control over iot_vlab.** It never starts, stops, spawns, kills, or resets the lab or its devices. All lifecycle management is done via iot_vlab's own tooling. APIOT only:

- Queries the iot_vlab REST API (read-only: `/topology`, `/library`, `/ready`)
- Sends raw network packets to the `192.168.100.0/24` lab subnet
- Uses `nmap` and protocol probes to fingerprint whatever iot_vlab has made reachable
- Applies `iptables` rules on the host (blue-team defenses only)

The test suite (`tests/test_isolation.py`) enforces this constraint.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Interactive CLI (core/cli.py)                                           │
│  API key → Lab check → Mission select → Continuous mission loop          │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  APIOT Agent Brain (core/agent.py)                                       │
│  LLM event loop | OpenRouter client | Overseer LLM | Rich TUI console    │
│  SQLite memory store (data/memory.db) — persists across sessions         │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (JSON tool calling — 19 tools)
┌──────────────────────────────────────────────────────────────────────────┐
│  Tool Registry & Dispatcher (core/tools/)                                │
│                                                                          │
│  RECON:  get_actionable_targets | inspect | run_command                  │
│  RED:    coap_send | modbus_request | tcp_send | udp_send                │
│          verify_crash | verify_shell                                     │
│  BLUE:   iptables_rule | protocol_block | modbus_fc_filter               │
│          coap_rate_limit | verify_patch                                  │
│  META:   list_patches | get_memory_context | create_tool                 │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Python Toolkit (toolkit/)                                               │
│  protocol_tools.py | defense_primitives.py | verifier.py | recon.py     │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
              HTTP REST (read-only)     Raw network packets / iptables
                         │                     │
┌──────────────────────────────────────────────────────────────────────────┐
│  iot_vlab — Emulated IoT Network (started & managed independently)       │
│  QEMU ARM/MIPS/Zephyr VMs + Python simulators on 192.168.100.0/24       │
│  REST API at http://localhost:5000                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **iot_vlab** | Must be running with at least one device active at `http://localhost:5000` |
| **OpenRouter API Key** | Set in `.env` or provided interactively |
| **Python 3.10+** | With `openai`, `python-dotenv`, `requests`, `rich` |
| **Kali Linux** | Required for nmap, iptables, raw socket access |
| **sudo** | Required for nmap scans and iptables operations |

---

## Installation

```bash
# 1. Start iot_vlab first (see iot_vlab README)
cd iot_vlab
sudo ./setup_network.sh
sudo python3 lab_api.py

# 2. Install APIOT
cd apiot
pip3 install -e .
```

Create `.env` in the `apiot/` directory:

```
OPENROUTER_API_KEY=sk-or-...
LLM_MODEL=anthropic/claude-3.5-sonnet   # optional — defaults to claude-3.5-sonnet
```

---

## Usage

### Interactive onboarding (recommended)

```bash
apiot
```

Checks your API key, verifies iot_vlab is reachable, shows discovered devices and past session history, then prompts for a mission mode.

### Direct launch (skip onboarding)

```bash
sudo python3 -m apiot.core.agent           # with TUI
sudo python3 -m apiot.core.agent --no-tui  # raw stdout
sudo python3 -m apiot.core.agent --no-overseer --no-tui  # disable oversight
```

### Mission Modes

| Mode | Description |
|------|-------------|
| **Full Purple Team** | Red phase (attack all devices) then Blue phase (patch and verify all findings). Default. |
| **Targeted Red** | Attack specific IPs you select. |
| **Novel Exploitation** | Creative attacks on devices already known from prior sessions. |
| **Blue Only** | Skip attacking — patch and verify existing open findings. |
| **Recon Only** | Scan and enumerate only. No exploits fired. |

---

## Two-Phase Purple Team Workflow

### Phase 1 — Red Team (Protocol Primitive Attacks)

The agent receives raw protocol primitives — it must reason about the byte-level encoding and craft malformed packets to trigger crashes:

| Target Port | Device Type | Tools |
|-------------|-------------|-------|
| UDP 5683 (CoAP) | Bare-metal OT / Smart Meter | `coap_send(options_hex, payload_hex, ...)` — agent reasons about option delta/length encoding to trigger option overflow |
| TCP 502 (Modbus/TCP) | Bare-metal OT / PLC | `modbus_request(function_code, data_hex, claimed_length)` — agent reasons about MBAP length field overflow |
| Any TCP | Linux gateway | `tcp_send(data_hex)` |
| Any UDP | Any device | `udp_send(data_hex)` |

After each probe: `verify_crash` (OT/MCU) or `verify_shell` (Linux) confirms impact.

### Phase 2 — Blue Team (Host-Level Defenses)

The agent identifies what made the exploit unique, then crafts a matching defense:

| Tool | Effect |
|------|--------|
| `iptables_rule(match_type, match_value, protocol, dport)` | Drop packets matching a specific byte pattern (hex_string match) or flag |
| `modbus_fc_filter(function_code)` | Block Modbus packets with a specific function code |
| `coap_rate_limit(rate, burst)` | Rate-limit CoAP UDP traffic |
| `protocol_block(protocol, port)` | Block an entire protocol/port combination |
| `verify_patch(target_ip, protocol, port, payload_hex)` | Replay the exact exploit bytes, confirm device survives |

---

## Overseer

An independent Overseer LLM monitors the main agent every N turns. It detects:
- Stalled behavior (repeating the same tool call)
- Phase-skipping (blue team actions before crash verified)
- Over-conservative behavior (not attempting attacks)

The Overseer injects strategic directives into the main conversation. It can be disabled with `--no-overseer` for ablation studies.

---

## Persistent Memory

APIOT maintains a SQLite memory store (`data/memory.db`) across sessions:

- All discovered device profiles and fingerprints
- Open vulnerabilities (unpatched findings)
- Active and verified patches
- Full tool call history with turn numbers, phases, and token counts

The memory store is also used by the experiment analysis pipeline (`scripts/analysis/`).

---

## Experiment Runner

For automated research experiments, use the scripts in `scripts/`:

```bash
# Single experiment run
python3 scripts/run_experiment.py \
  --rq RQ1_RQ2 --protocol coap --topology T1 --run-id 1 \
  --overseer on --impairment none

# Full 42-run suite (RQ1–RQ6)
sudo bash scripts/run_all_experiments.sh

# Check progress
python3 scripts/check_results.py

# Run analysis (after experiments complete)
python3 scripts/analysis/rq1_capability.py
python3 scripts/analysis/rq2_behaviour.py
python3 scripts/analysis/rq3_oversight.py
```

Each run produces `results/<rq>/<config>/`:
- `run_result.json` — outcome, duration, model, overseer flag
- `attack_log.json` — every tool call with timestamps
- `memory.db` — SQLite tool history with phase labels
- `session.log` — full TUI output

---

## References

- [apiot/CLAUDE.md](CLAUDE.md) — Full architecture and design patterns
- [RED_TEAM_RUNBOOK.md](RED_TEAM_RUNBOOK.md) — Behavioral constraints and attack flow
- [iot_vlab](https://github.com/Adelsamir01/iot_vlab) — The virtual IoT lab that APIOT targets
