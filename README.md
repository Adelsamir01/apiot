# APIOT — Agentic Purple IoT Toolkit

An LLM-driven Red/Blue agent framework for IoT security testing. APIOT provides reconnaissance, exploit, verification, and remediation tools that an external LLM agent (e.g. Cursor, Claude) orchestrates via a CLI interface. The LLM is the brain; APIOT is the tool harness.

## Overview

- **Red Agent:** Discovers hosts, fingerprints them, selects exploits, executes attacks, verifies outcomes, and logs findings.
- **Blue Agent:** Analyzes attack payloads, generates defensive signatures, applies iptables virtual patches, and verifies remediation.
- **Purple Teaming:** Closed-loop validation — Red finds exploits, Blue patches them, and the system verifies the patch blocks the attack.

All attacks target the `192.168.100.0/24` lab subnet. APIOT expects the **iot_vlab** REST API to be running at `http://localhost:5000`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  LLM Agent (Cursor/Claude) — The Brain                                   │
│  Reads JSON output, reasons, issues CLI commands                         │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  agent_loop.py — CLI Tool Harness                                        │
│  get_state | get_targets | attack | verify_crash | verify_shell | evolve  │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Core: mapper, state, attack_log, analyzer, evolve, verifier_blue         │
│  Toolkit: recon, ot_exploits, linux_exploits, verifier, defender,         │
│           lab_client, visualize                                                                 │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  iot_vlab — REST API :5000 (lab_client)                                  │
│  Spawn / kill / topology / reset_lab                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **iot_vlab** | Virtual lab must be running. See `../iot_vlab/README.md`. |
| **Lab API** | `sudo python3 iot_vlab/lab_api.py` on port 5000 |
| **Python 3.10+** | With `requests` (for lab_client) |
| **sudo** | For nmap scans, recon, and iptables |
| **Kali Linux** | Tested on Kali 6.16.8 aarch64; any Debian-based with nmap works |

---

## Installation

From the project root (`llm_iot/`):

```bash
# Ensure iot_vlab is set up
cd iot_vlab
sudo ./setup_network.sh
./download_firmware.sh
cd ..

# Install Python deps (if not already)
pip3 install requests
```

Run from project root so `apiot` is importable:

```bash
cd /path/to/llm_iot
export PYTHONPATH="${PWD}:${PYTHONPATH}"
```

---

## Quick Start

```bash
# 1. Start the lab API
sudo python3 iot_vlab/lab_api.py &

# 2. Spawn targets (or use full_autonomous_run.py setup)
curl -s -X POST http://localhost:5000/spawn -H 'Content-Type: application/json' \
  -d '{"firmware_id": "zephyr_coap"}'
curl -s -X POST http://localhost:5000/spawn -H 'Content-Type: application/json' \
  -d '{"firmware_id": "dvrf_v03"}'

# 3. Wait for boot (20s for Linux, ~5s for Zephyr)
sleep 20

# 4. Run the mapper
sudo python3 -m apiot.core.mapper

# 5. Visualize the network map
python3 -m apiot.toolkit.visualize

# 6. Get actionable targets (for LLM)
sudo python3 -m apiot.core.agent_loop get_targets

# 7. Attack & verify (example)
sudo python3 -m apiot.core.agent_loop attack coap_option_overflow 192.168.100.35
sudo python3 -m apiot.core.agent_loop verify_crash 192.168.100.35
```

---

## Project Structure

```
apiot/
├── README.md
├── RED_TEAM_RUNBOOK.md
├── core/
│   ├── agent_loop.py
│   ├── analyzer.py
│   ├── attack_log.py
│   ├── evolve.py
│   ├── mapper.py
│   ├── state.py
│   └── verifier_blue.py
├── toolkit/
│   ├── defender.py
│   ├── dynamic_udp_probe.py
│   ├── lab_client.py
│   ├── linux_exploits.py
│   ├── ot_exploits.py
│   ├── recon.py
│   ├── verifier.py
│   └── visualize.py
├── data/
│   ├── network_state.json
│   ├── attack_log.json
│   └── remediation_log.json
└── tests/
    ├── test_phase1.py
    ├── test_phase2_tools.py
    ├── full_autonomous_run.py
    └── closed_loop_remediation.py
```

---

## Core Modules

### `agent_loop.py` — CLI Tool Harness

Exposes commands for the LLM. All output is JSON.

| Command | Args | Description |
|---------|------|-------------|
| `get_state` | — | Full network state (hosts, fingerprints, vulnerabilities) |
| `get_targets` | — | Actionable targets with attack surfaces and available tools |
| `stealth_check` | `<ip>` | Packet loss to target; recommendation: proceed / throttle / skip |
| `attack` | `<tool> <ip> [key=val...]` | Execute exploit tool |
| `verify_crash` | `<ip>` | Check if target crashed; auto-logs vulnerability if verified |
| `verify_shell` | `<ip> [port]` | Check shell access; auto-logs if verified |
| `evolve` | `<ip> [port]` | Generate and run dynamic UDP probe |
| `log_summary` | — | Attack metrics (steps, packets, crashes, packets/vuln) |
| `reset_logs` | — | Clear attack_log.json and vulnerabilities |

**Available tools:** `modbus_write_coil`, `modbus_mbap_overflow`, `coap_option_overflow`, `http_cmd_injection`, `brute_force_telnet`

### `mapper.py` — Autonomous Network Mapper

Run once before attack phase:

```bash
sudo python3 -m apiot.core.mapper
```

1. Ping-sweeps `192.168.100.10-50` (via nmap)
2. Fingerprints each host on ports `22,23,80,443,502,4242,5683`
3. Classifies by port heuristics:
   - **Bare-Metal OT Sensor:** OT ports only (502, 4242, 5683) → Zephyr / Cortex-M3
   - **Linux Gateway/Router:** IT ports (22, 23, 80, 443)
4. Persists to `data/network_state.json`

### `state.py` — AgentMemory

`AgentMemory` stores:

- `discovered_hosts` — IP, MAC, vendor
- `fingerprints` — Ports, classification, attack_surface
- `active_vulnerabilities` — Verified findings

### `attack_log.py` — AttackLogger

Append-only log of every attack step: target, tool, payload_hex, outcome, packets_sent.

### `analyzer.py` — PayloadAnalyzer (Blue Agent)

Reads `attack_log.json` and produces defensive signatures:

| Attack | Signature Type | Filter |
|--------|----------------|--------|
| `coap_option_overflow` | length | UDP:5683, length 0:7 → DROP |
| `modbus_mbap_overflow` | length | TCP:502, length 300:65535 → DROP |
| `modbus_write_coil` | u32 | FC 0x05 at byte 7 → DROP |
| `http_cmd_injection` | string | `/bin/sh` in HTTP → DROP |

### `evolve.py` — Self-Evolution

When built-in exploits fail, generates `dynamic_udp_probe.py` and runs it. Used by `agent_loop evolve`.

### `verifier_blue.py` — Blue Agent Verification

- `ensure_sensor_online()` — Respawn crashed sensor via lab API
- `replay_attack()` — Replay the exact exploit payload
- `verify_patch_holds()` — Confirm sensor survives (patch blocked attack)
- `mark_remediated()` — Update network_state with VERIFIED_SECURE

---

## Toolkit Modules

| Module | Purpose |
|--------|---------|
| `lab_client` | REST client for iot_vlab API (library, spawn, topology, kill, reset) |
| `recon` | `scan_subnet()`, `fingerprint_target()`, `udp_probe()` — nmap wrappers |
| `ot_exploits` | Modbus TCP: `modbus_write_coil`, `modbus_mbap_overflow`; CoAP: `coap_option_overflow` |
| `linux_exploits` | `http_cmd_injection`, `brute_force_telnet` |
| `verifier` | `verify_crash()`, `verify_shell()` — post-exploit verification |
| `defender` | `generate_iptables_rule()`, `apply_patch()`, `remove_patch()` |
| `visualize` | ASCII table of network map from `network_state.json` |

---

## Target Classification

| Open Ports | Category | Attack Surface |
|------------|----------|----------------|
| 502       | Bare-Metal OT Sensor (PLC) | `modbus_write_coil`, `modbus_mbap_overflow` |
| 5683      | Bare-Metal OT Sensor (CoAP) | `coap_option_overflow` |
| 4242      | Bare-Metal OT Sensor (Echo) | `tcp_echo_probe` |
| 22        | Linux Gateway | `ssh_brute_force` (reserved) |
| 23        | Linux Gateway | `brute_force_telnet` |
| 80 / 443  | Linux Gateway | `http_cmd_injection` |

---

## Red Agent Workflow

1. **Phase 0:** `sudo python3 -m apiot.core.mapper`
2. **Gate:** Ensure `network_state.json` has targets with `attack_surface`
3. **Loop:**
   - `get_targets` → pick target and tool
   - `attack <tool> <ip>`
   - `verify_crash <ip>` or `verify_shell <ip> [port]`
   - Logged findings appear in `active_vulnerabilities`
4. **Iterate:** Re-read state; crashed targets may have disappeared; continue until all assessed.

See `RED_TEAM_RUNBOOK.md` for the full decision tree and constraints.

---

## Blue Agent Workflow

1. **Analyze:** `PayloadAnalyzer().analyze_attack_log()` → signatures
2. **Patch:** `defender.generate_iptables_rule(sig)` → `apply_patch(rule, sig)`
3. **Verify:** `verifier_blue.replay_attack()` → `verify_patch_holds()` → sensor still alive
4. **Log:** `mark_remediated(vuln_id, ip, attack, rule)`

---

## Data Files

| File | Purpose |
|------|---------|
| `data/network_state.json` | Hosts, fingerprints, classifications, vulnerabilities |
| `data/attack_log.json` | Attack steps with payloads and outcomes |
| `data/remediation_log.json` | Applied patches and timing (TTP) |

---

## Tests

| Test | Command | Purpose |
|------|---------|---------|
| Phase 1 | `sudo python3 -m apiot.tests.test_phase1` | Lab API, spawn, recon, fingerprint, persistence |
| Phase 2 | `sudo python3 -m apiot.tests.test_phase2_tools` | Phase 2 toolkit |
| Full autonomous | `sudo python3 apiot/tests/full_autonomous_run.py setup` then `teardown` / `verify` | Lab setup + teardown for LLM-driven runs |
| Closed-loop | `sudo python3 apiot/tests/closed_loop_remediation.py` | End-to-end: attack → analyze → patch → verify patch holds |

---

## Constraints

- Attacks only within `192.168.100.0/24`
- Always call `verify_*` after each attack — do not rely on attack return value alone
- Log findings to `AgentMemory` immediately
- If a target stops responding, move on; do not retry indefinitely

---

## References

- [RED_TEAM_RUNBOOK.md](RED_TEAM_RUNBOOK.md) — Step-by-step Red Agent workflow
- [../iot_vlab/README.md](../iot_vlab/README.md) — Virtual lab setup and usage
