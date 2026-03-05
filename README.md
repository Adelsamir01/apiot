# APIOT — Agentic Purple IoT Toolkit

An **autonomous, LLM-driven Purple Team agent** for IoT security testing. APIOT uses OpenRouter to orchestrate a continuous `think → act → observe` loop against a virtualized IoT network powered by [iot_vlab](https://github.com/Adelsamir01/iot_vlab).

---

## What It Does

APIOT runs as a self-contained terminal application. Once started, it will:

1. Auto-start the `iot_vlab` REST API and spawn target devices
2. Map the target subnet and fingerprint every host
3. Autonomously select and execute exploits against each target
4. Verify every attack result (crash / shell access)
5. Display everything in a live split-panel terminal UI

No human input is needed after launch.

---

## System Requirements

| Requirement | Details |
|---|---|
| **OS** | Any Debian-based Linux (Ubuntu, Debian, Kali, etc.). Kali is convenient as it ships with `nmap` and QEMU pre-installed, but Ubuntu/Debian work equally well after running `apt install nmap qemu-system-arm qemu-system-mips`. macOS is supported for the agent layer only — the QEMU lab requires Linux. |
| **Python** | 3.10+ |
| **iot_vlab** | Must be cloned as a sibling directory to `apiot` |
| **OpenRouter API Key** | [openrouter.ai](https://openrouter.ai) |
| **sudo** | Required for nmap scans and iptables operations |

---

## Installation

```bash
# 1. Clone both repos side by side
git clone https://github.com/Adelsamir01/apiot
git clone https://github.com/Adelsamir01/iot_vlab

# 2. Set up iot_vlab (Linux only)
cd iot_vlab
sudo ./setup_network.sh
./download_firmware.sh
cd ..

# 3. Install APIOT
cd apiot
pip3 install -e .
```

---

## Usage

```bash
sudo apiot
```

The interactive setup screen will prompt you for:

- **OpenRouter API Key** — saved to `.env` automatically on first run
- **Target subnet** — defaults to `192.168.100.0/24`
- **Lab bootstrap** — whether to auto-start `iot_vlab` and spawn devices
- **TUI** — enable or disable the split-panel terminal UI

### Flags

```bash
sudo python3 -m apiot.core.agent --skip-bootstrap   # Skip lab auto-start
sudo python3 -m apiot.core.agent --no-tui           # Plain text output
```

---

## Terminal UI

The agent renders a vertically split terminal dashboard:

```
┌────── Agent Flow ──────┐┌────── Network Map ───────┐
│ ⚡ get_actionable_...  ││ IP          Status        │
│ → 1 target found       ││ 192.168.100.35  CRASHED   │
│                        ││ 192.168.100.42  ONLINE    │
│ ⚡ execute_exploit()   ││                           │
│ → coap_option_overflow ││ Hosts: 2 | Vulns: 1       │
└────────────────────────┘└───────────────────────────┘
```

---

## How It Works

```
apiot (core/cli.py)
  └── APIOTAgent (core/agent.py)                ← OpenRouter event loop
        ├── Lab Bridge (core/lab_bridge.py)      ← auto-starts iot_vlab
        ├── Skills Registry (core/tools/)        ← 7 JSON Schema tools
        │     ├── get_actionable_targets
        │     ├── execute_exploit
        │     ├── verify_crash / verify_shell
        │     └── manage_lab
        ├── Toolkit (toolkit/)                   ← actual attack code
        │     ├── ot_exploits.py  (Modbus, CoAP)
        │     ├── linux_exploits.py (Telnet, HTTP)
        │     └── verifier.py
        └── TUI (core/tui.py)                   ← rich split-panel UI
```

---

## Available Tools

| Tool | Description |
|---|---|
| `get_network_state` | Returns full network context |
| `get_actionable_targets` | Lists targets with attack surfaces |
| `stealth_check` | Measures packet loss before attacking |
| `execute_exploit` | Fires a specific exploit (`modbus_write_coil`, `coap_option_overflow`, `http_cmd_injection`, `brute_force_telnet`, `modbus_mbap_overflow`) |
| `verify_crash` | Confirms target went offline post-attack |
| `verify_shell` | Confirms shell access was gained |
| `manage_lab` | Spawn / kill / reset `iot_vlab` devices |

---

## Configuration

Create `apiot/.env` manually or let the interactive CLI create it:

```env
OPENROUTER_API_KEY="sk-or-v1-..."
LLM_MODEL="anthropic/claude-3.5-sonnet"
```

---

## References

- [RED_TEAM_RUNBOOK.md](RED_TEAM_RUNBOOK.md) — Behavioral constraints embedded in the agent's system prompt
- [iot_vlab](https://github.com/Adelsamir01/iot_vlab) — The virtual IoT lab this agent operates against
