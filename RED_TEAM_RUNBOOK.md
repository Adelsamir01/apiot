# Red Team Runbook — Agentic Purple IoT

## Purpose

Step-by-step operational loop for the LLM Red Agent.
Each cycle reads the current network state, selects an attack,
executes it, verifies the outcome, and logs results.

---

## Pre-Conditions

- `iot_vlab` API running on `http://localhost:5000`.
- All toolkit modules importable (`toolkit.lab_client`, `toolkit.recon`,
  `toolkit.ot_exploits`, `toolkit.linux_exploits`, `toolkit.verifier`).

---

## Phase 0 — Reconnaissance (MANDATORY)

The Red Agent **MUST NOT** select exploit tools until the network map
is fully generated and every target is categorized.

```bash
sudo python3 -m apiot.core.mapper
```

This runs the autonomous mapper which:

1. Ping-sweeps `192.168.100.0/24` to discover live hosts.
2. Fingerprints each host on ports `22,23,80,443,502,4242,5683`.
3. Classifies each target as **Bare-Metal OT Sensor** or **Linux Gateway/Router**
   using port-based heuristics and MAC address matching.
4. Persists the enriched map to `data/network_state.json`.

Verify the map visually:

```bash
python3 -m apiot.toolkit.visualize
```

**Gate:** Proceed to the Main Loop ONLY when `data/network_state.json`
contains at least one target with a non-empty `attack_surface`.

---

## Main Loop

### Step 1 — Load Context

```python
from apiot.core.state import AgentMemory
memory = AgentMemory()
ctx = memory.get_full_context()
```

Read `ctx["discovered_hosts"]` and `ctx["fingerprints"]`.
Build a target list of `(ip, open_ports)` tuples.

### Step 2 — Classify Each Target

For every IP in the target list, inspect its fingerprint:

| Open Port | Service Hint     | Target Class      | Attack Module            |
|-----------|------------------|-------------------|--------------------------|
| 502       | Modbus/TCP       | OT PLC            | `toolkit.ot_exploits`    |
| 5683      | CoAP (UDP)       | OT Sensor         | `toolkit.ot_exploits`    |
| 4242      | Echo (TCP/UDP)   | OT Sensor         | `toolkit.ot_exploits`    |
| 22        | SSH              | Linux Gateway     | `toolkit.linux_exploits` |
| 23        | Telnet           | Linux Gateway     | `toolkit.linux_exploits` |
| 80/443    | HTTP/HTTPS       | Linux Gateway     | `toolkit.linux_exploits` |

### Step 3 — Select & Execute Attack

Follow priority order per target class:

#### OT Targets (Modbus port 502)

1. `ot_exploits.modbus_write_coil(ip, action="off")`
   — Attempt to toggle a coil; proves write access.
2. `ot_exploits.modbus_mbap_overflow(ip)`
   — Fuzz the MBAP length field; may crash the LwIP stack.

#### OT Targets (CoAP port 5683)

1. `ot_exploits.coap_option_overflow(ip)`
   — Malformed option delta/length; may crash the CoAP parser.

#### Linux Gateways (SSH/Telnet)

1. `linux_exploits.brute_force_telnet(ip)`
   — Try default credentials (`root:root`, `root:password`, `admin:admin`).
2. If HTTP is open:
   `linux_exploits.http_cmd_injection(ip, port=80, path="/", param="cmd", payload="id")`

### Step 4 — Verify Outcome

After every attack call, run the appropriate verifier:

- **Crash-type attacks** (overflow / fuzz):
  ```python
  from apiot.toolkit.verifier import verify_crash
  result = verify_crash(ip, known_ports=[502])
  ```
  If `result["verified"] is True` → target crashed → attack succeeded.

- **Shell-access attacks** (brute force / injection):
  ```python
  from apiot.toolkit.verifier import verify_shell
  result = verify_shell(ip, port=23, trigger_cmd="echo APIOT_PWNED")
  ```
  If `result["verified"] is True` → shell obtained → attack succeeded.

### Step 5 — Log Results

For every verified success:

```python
import time, hashlib
vuln_id = hashlib.md5(f"{ip}:{attack_name}:{time.time()}".encode()).hexdigest()[:12]
memory.add_vulnerability(vuln_id, {
    "ip": ip,
    "attack": attack_name,
    "payload_hex": result.get("payload_hex", ""),
    "verification": verification_result,
    "timestamp": time.time(),
})
```

### Step 6 — Iterate

Return to **Step 1**. Re-read state (targets may have crashed and
disappeared). Continue until all reachable targets have been assessed.

---

## Decision Tree (Quick Reference)

```
for ip, fingerprint in targets:
    if 502 in fingerprint.ports:
        -> modbus_write_coil(ip)
        -> modbus_mbap_overflow(ip)
        -> verify_crash(ip, [502])
    if 5683 in fingerprint.ports:
        -> coap_option_overflow(ip)
        -> verify_crash(ip, [5683])
    if 23 in fingerprint.ports:
        -> brute_force_telnet(ip)
        -> verify_shell(ip, port=23)
    if 80 in fingerprint.ports:
        -> http_cmd_injection(ip)
        -> verify_shell(ip, port=23)
    if 22 in fingerprint.ports:
        -> (reserved for ssh_brute_force — Phase 3)
```

---

## Constraints

- Never run attacks outside the `192.168.100.0/24` lab subnet.
- Always call a `verify_*` function after each attack — do not
  assume success from the attack return value alone.
- Log every finding to `AgentMemory` immediately.
- If a target stops responding, move on; do not retry indefinitely.
