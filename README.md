# APIOT — Agentic Purple IoT Toolkit

APIOT is a **fully autonomous, LLM-driven Red/Blue agent orchestrator** for IoT security testing. It uses a continuous `thought → action → observation` loop to autonomously explore, attack, verify vulnerabilities, and then apply and verify defenses — all within a virtualized IoT network provided by **iot_vlab**.

The LLM (via OpenRouter) acts as the reasoning brain. APIOT provides the native JSON Schema tools, network mapping, exploit primitives, and session memory.

---

## Relationship to iot_vlab

APIOT is built as a **client of [iot_vlab](https://github.com/Adelsamir01/iot_vlab)**. The two systems are designed to run side-by-side:

```
iot_vlab                              APIOT
─────────────────────────────────     ──────────────────────────────────
Emulates IoT devices in QEMU          Autonomously attacks those devices
Bridges them to 192.168.100.0/24  ←── Scans, fingerprints, exploits
Exposes REST API on :5000             Queries /topology, /library, /ready
Manages device lifecycle              NEVER touches device lifecycle
```

**APIOT has zero control over iot_vlab.** It never starts, stops, spawns, kills, or resets the lab or its devices. All lifecycle management is done manually or via iot_vlab's own tooling. APIOT only:

- Queries the iot_vlab REST API (read-only: `/api/topology`, `/api/library`, `/api/ready`)
- Sends raw network packets to the `192.168.100.0/24` lab subnet
- Uses `nmap` and protocol probes to fingerprint whatever iot_vlab has made reachable

The test suite (`tests/test_isolation.py`) enforces this constraint and will fail if any lifecycle control leaks in.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Interactive CLI (core/cli.py)                                           │
│  API key → Lab check → Mission select → Continuous mission loop         │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  APIOT Agent Brain (core/agent.py)                                       │
│  LLM event loop | OpenRouter client | Overseer LLM | Rich TUI console   │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (JSON tool calling)
┌──────────────────────────────────────────────────────────────────────────┐
│  Tool Registry & Dispatcher (core/tools/)                                │
│  get_targets | execute_exploit | verify_crash | verify_shell | inspect   │
│  analyze_attacks | apply_patch | verify_patch | run_command | create_tool│
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Python Toolkit (toolkit/)                                               │
│  ot_exploits, linux_exploits, verifier, recon, defender                 │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
              HTTP REST (read-only)     Raw network packets
                         │                     │
┌──────────────────────────────────────────────────────────────────────────┐
│  iot_vlab — Emulated IoT Network (started & managed independently)       │
│  QEMU ARM/MIPS/Zephyr VMs bridged to 192.168.100.0/24                  │
│  REST API at http://localhost:5000                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **iot_vlab** | Must be running with at least one device active at `http://localhost:5000` |
| **OpenRouter API Key** | Provided interactively on first run, or set in `.env` |
| **Python 3.10+** | With `openai`, `python-dotenv`, `requests`, `rich` |
| **Kali Linux** | Recommended (nmap, iptables, sshpass, and raw socket access required) |
| **sudo** | Required for nmap scans, recon, and iptables patch operations |

---

## Installation

```bash
# 1. Start iot_vlab first (in a separate terminal — see iot_vlab README)
cd iot_vlab
sudo ./setup_network.sh
sudo python3 lab_api.py

# 2. Install APIOT
cd apiot
pip3 install -e .
```

---

## Usage

```bash
apiot
```

The onboarding flow checks your API key, verifies iot_vlab is reachable, displays known devices and past session history from the persistent memory store, then prompts for a mission mode. After each mission completes, it asks if you want to run another — carrying all discovered findings and device profiles forward automatically.

### Mission Modes

| Mode | Description |
|------|-------------|
| **Full Purple Team** | Red phase (attack all devices) then Blue phase (patch and verify all findings). Default. |
| **Targeted Red** | Attack specific IPs you select. Skips unreachable or unselected devices. |
| **Novel Exploitation** | Creative attacks on devices already known from prior sessions. Tries new vectors. |
| **Blue Only** | Skip attacking — patch and verify existing open findings from the memory store. |
| **Recon Only** | Scan and enumerate only. No exploits fired. |

### Direct Launch (skip onboarding)

```bash
sudo python3 -m apiot.core.agent           # with TUI
sudo python3 -m apiot.core.agent --no-tui  # raw stdout
```

Requires `OPENROUTER_API_KEY` and optionally `LLM_MODEL` in `.env`.

### Manual Tool Harness

Test individual tools outside the LLM loop:

```bash
sudo python3 -m apiot.core.agent_loop get_state
sudo python3 -m apiot.core.agent_loop get_targets
sudo python3 -m apiot.core.agent_loop attack modbus_write_coil 192.168.100.35
```

---

## Two-Phase Purple Team Workflow

**Phase 1 — Red Team (Offensive):**

| Detected Port | Device Type | Available Exploits |
|--------------|-------------|--------------------|
| 502 (Modbus) | Bare-metal OT / PLC | `modbus_write_coil`, `modbus_mbap_overflow` |
| 5683 (CoAP) | Bare-metal OT / Sensor | `coap_option_overflow` |
| 23 (Telnet) | Linux Gateway | `brute_force_telnet` |
| 22 (SSH) | Linux Gateway | `brute_force_ssh` |
| 80 / 443 (HTTP) | Linux Gateway | `http_cmd_injection` |

Each exploit is immediately followed by `verify_crash` or `verify_shell` to confirm impact.

**Phase 2 — Blue Team (Defensive):**

1. `analyze_attacks` extracts iptables-compatible signatures from the attack log
2. `apply_patch` deploys FORWARD drop rules on the host
3. `verify_patch` replays the original attack to confirm the device survives

---

## Persistent Memory

APIOT maintains a SQLite memory store (`data/memory.db`) across sessions. Between missions it remembers:

- All discovered device profiles and fingerprints
- Open vulnerabilities (unpatched findings)
- Active and verified patches
- Full tool call history with outcomes

The CLI surfaces this at the start of each mission so the agent can continue where the previous run left off.

---

## References

- [RED_TEAM_RUNBOOK.md](RED_TEAM_RUNBOOK.md) — Behavioral constraints and attack flow logic
- [iot_vlab](https://github.com/Adelsamir01/iot_vlab) — The virtual IoT lab that APIOT targets
