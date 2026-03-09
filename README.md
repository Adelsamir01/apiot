# APIOT — Agentic Purple IoT Toolkit

APIOT is a **fully autonomous, LLM-driven Red/Blue agent orchestrator** for IoT security testing. It uses a continuous `thought -> action -> observation` loop to autonomously explore, attack, and verify vulnerabilities within a virtualized IoT network.

The LLM (via OpenRouter) acts as the brain, while APIOT provides the native JSON Schema tools, network mapping capabilities, and read-only lab inspection.

## Overview

- **Interactive Terminal App:** Run `apiot` and a guided onboarding flow walks you through API key setup, lab connectivity, and mode selection.
- **Fully Autonomous Daemon:** Once configured, the LLM takes over and handles everything from reconnaissance to vulnerability verification.
- **Native Tool Calling:** The LLM interacts directly with APIOT's hacking toolkit using strict OpenAI-compatible JSON schemas.
- **Communication-Only Lab Access:** APIOT communicates with `iot_vlab` via its REST API but **never starts, stops, spawns, kills, or resets** the lab or its devices. You manage `iot_vlab` manually.
- **Rich Operator Console:** A split-terminal UI shows the agent's inner monologue, tool executions, and a live network topology map in real-time.

All attacks target the `192.168.100.0/24` lab subnet provided by **iot_vlab**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Interactive CLI (core/cli.py)                                           │
│  Onboarding: API key → Lab check → Topology → Mapper → Mode select      │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  APIOT Agent Brain (core/agent.py)                                       │
│  Continuous Event Loop | OpenRouter Client | Rich TUI Console            │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (JSON Tool Calling)
┌──────────────────────────────────────────────────────────────────────────┐
│  The Skills Registry (core/tools/registry.py & dispatcher.py)            │
│  get_targets | execute_exploit | verify_crash | verify_shell | inspect   │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Python Toolkit (toolkit/)                                               │
│  mapper, recon, ot_exploits, linux_exploits, verifier, defender          │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (HTTP REST — read-only + network probes)
┌──────────────────────────────────────────────────────────────────────────┐
│  iot_vlab — Emulated IoT Network (started & managed manually)            │
│  QEMU ARM/MIPS VMs bridged to 192.168.100.0/24                           │
└──────────────────────────────────────────────────────────────────────────┘
```

### Isolation Model

APIOT treats `iot_vlab` as an **external, independently managed system**:

- **Allowed:** Querying the lab REST API (`/topology`, `/library`), scanning the network, sending exploit payloads over the wire.
- **Forbidden:** Starting/stopping the lab API, spawning/killing/resetting devices, accessing `iot_vlab` filesystem paths, running `iot_vlab` scripts.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **OpenRouter API Key** | Provided interactively on first run, or set in `apiot/.env` |
| **Python 3.10+** | With `openai`, `python-dotenv`, `requests`, and `rich` |
| **iot_vlab** | Must be running and accessible at `http://localhost:5000` |
| **Kali Linux** | Recommended OS (required for the underlying QEMU emulation) |
| **sudo** | Required for nmap scans, recon, and iptables operations |

---

## Installation

```bash
# 1. Start iot_vlab manually (in a separate terminal)
cd iot_vlab
sudo ./setup_network.sh
./download_firmware.sh
sudo python3 lab_api.py
# Spawn targets via the iot_vlab API or interactive wizard

# 2. Install APIOT
cd apiot
pip3 install -e .
```

---

## Usage

```bash
apiot
```

The interactive onboarding flow will guide you through:

```
    ___    ____  ________  ______
   /   |  / __ \/  _/ __ \/_  __/
  / /| | / /_/ // // / / / / /
 / ___ |/ ____// // /_/ / / /
/_/  |_/_/   /___/\____/ /_/

  Autonomous Purple IoT Toolkit

  [1/5] OpenRouter API Key
        OK  Key loaded: sk-or-v1-c04...662d

  [2/5] Lab Connectivity
        OK  iot_vlab REST API is reachable at http://localhost:5000

  [3/5] Device Topology
        OK  2 device(s) found:
        ┌──────────────┬──────────────────┬───────┐
        │ Firmware      │ IP               │ Alive │
        ├──────────────┼──────────────────┼───────┤
        │ zephyr_coap   │ 192.168.100.35   │  YES  │
        │ dvrf_v03      │ 192.168.100.12   │  YES  │
        └──────────────┴──────────────────┴───────┘

  [4/5] Network Mapping
        OK  Mapped 2 target(s). network_state.json updated.

  [5/5] Mission Mode
        1  Autonomous Red Team
           Fully autonomous attack + verification loop.

        2  Manual CLI Harness
           You drive tool commands one at a time via the CLI.

        Select mode [1]:
```

### Modes

| Mode | Description |
|------|-------------|
| **Autonomous Red Team** | The LLM takes full control. It discovers targets, selects exploits, fires payloads, and verifies results. You watch via the TUI. |
| **Manual CLI Harness** | You drive each step yourself via the command line. Useful for learning, debugging, or scripted workflows. |

### Direct Agent Launch (no onboarding)

If you prefer to skip the interactive flow:

```bash
cd /path/to/llm_iot
export PYTHONPATH="${PWD}"
sudo python3 -m apiot.core.agent          # with TUI
sudo python3 -m apiot.core.agent --no-tui  # raw stdout
```

This requires `OPENROUTER_API_KEY` and `LLM_MODEL` to be set in `apiot/.env` and `iot_vlab` to be running with devices.

---

## Project Structure

```
apiot/
├── README.md
├── RED_TEAM_RUNBOOK.md        # Behavioral constraints for the Agent
├── .env                       # API keys and model configuration
├── core/
│   ├── cli.py                 # Interactive terminal entry point + onboarding
│   ├── agent.py               # The main autonomous daemon loop
│   ├── lab_bridge.py          # Pre-flight check (verifies lab is online)
│   ├── tui.py                 # Rich split-terminal UI renderer
│   ├── tools/
│   │   ├── registry.py        # OpenAPI JSON schemas for LLM tool calling
│   │   └── dispatcher.py      # Routes tool calls to the toolkit functions
│   ├── state.py               # JSON File I/O for network state persistence
│   ├── mapper.py              # Autonomous network mapper (nmap wrappers)
│   ├── analyzer.py            # Blue team defensive payload analyzer
│   └── verifier_blue.py       # Blue team patch verification
├── toolkit/
│   ├── ot_exploits.py         # Modbus and CoAP attack implementations
│   ├── linux_exploits.py      # Telnet and HTTP attack implementations
│   ├── verifier.py            # Post-exploit crash and shell verification
│   ├── lab_client.py          # Read-only REST client for iot_vlab
│   └── recon.py               # Underlying scanning wrappers
├── tests/
│   ├── test_isolation.py      # Verifies APIOT cannot control iot_vlab lifecycle
│   ├── test_guardrails.py     # Verifies API key + lab pre-flight gates
│   ├── test_phase1.py         # Integration test (requires running lab)
│   ├── test_phase2_tools.py   # Offline packet construction validation
│   ├── full_autonomous_run.py # Infrastructure check + verification
│   └── closed_loop_remediation.py  # Purple team closed-loop test
└── data/
    ├── network_state.json     # Live DB of discovered hosts and vulns
    └── attack_log.json        # Append-only log of fired payloads
```

---

## Target Classification & Exploit Mapping

| Open Ports | Category | Attack Surface |
|------------|----------|----------------|
| 502       | Bare-Metal OT Sensor (PLC) | `modbus_write_coil`, `modbus_mbap_overflow` |
| 5683      | Bare-Metal OT Sensor (CoAP) | `coap_option_overflow` |
| 23        | Linux Gateway | `brute_force_telnet` |
| 80 / 443  | Linux Gateway | `http_cmd_injection` |

---

## References

- [RED_TEAM_RUNBOOK.md](RED_TEAM_RUNBOOK.md) — The behavioral constraints and logic flow guiding the Agent's decisions.
- [iot_vlab](https://github.com/Adelsamir01/iot_vlab) — The underlying Virtual IoT lab framework.
