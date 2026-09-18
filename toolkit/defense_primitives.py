"""defense_primitives.py — Low-level defensive primitives for APIOT.

These are the raw building blocks the agent uses to craft and deploy virtual
patches. Unlike the old analyze_attacks + apply_patch workflow, these require
the agent to reason about the threat and construct the appropriate filter.

iptables_rule    — add/remove one iptables rule (agent writes full match expression)
protocol_block   — block all traffic to a port with a simple DROP
modbus_fc_filter — filter packets containing a specific Modbus function code
coap_rate_limit  — rate-limit CoAP traffic using iptables hashlimit

All rules are applied to both FORWARD (routed QEMU traffic via TAP) and
INPUT (software simulator IP aliases on br0) chains automatically.
"""

import json
import subprocess
import time
from pathlib import Path

REMEDIATION_LOG = Path(__file__).resolve().parent.parent / "data" / "remediation_log.json"


def _run_iptables(cmd: str, timeout: int = 10) -> tuple[int, str]:
    """Run an iptables command and return (returncode, stderr)."""
    proc = subprocess.run(
        f"sudo {cmd}", shell=True, capture_output=True, text=True, timeout=timeout
    )
    return proc.returncode, proc.stderr.strip()


def _log_patch(rule: str, description: str, applied: bool, elapsed_s: float) -> None:
    """Append to remediation_log.json."""
    REMEDIATION_LOG.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    if REMEDIATION_LOG.exists() and REMEDIATION_LOG.stat().st_size > 0:
        try:
            entries = json.loads(REMEDIATION_LOG.read_text())
        except json.JSONDecodeError:
            pass
    entries.append({
        "timestamp": time.time(),
        "rule": rule,
        "description": description,
        "applied": applied,
        "elapsed_s": elapsed_s,
    })
    REMEDIATION_LOG.write_text(json.dumps(entries, indent=2))


# ── Primary building block ────────────────────────────────────────────────────

def iptables_rule(chain: str = "FORWARD", protocol: str = "tcp",
                  dport: int = 502, match_type: str = "plain",
                  match_value: str = "", algo: str = "bm",
                  verdict: str = "DROP", op: str = "add") -> dict:
    """Add or remove one iptables rule on the host.

    The same rule is applied to both the specified chain and INPUT so it
    protects both QEMU devices (FORWARD) and software simulators (INPUT).

    Parameters
    ----------
    chain       : primary chain — "FORWARD" or "INPUT"
    protocol    : "tcp" or "udp"
    dport       : destination port to match
    match_type  : "plain"      — no payload match, just protocol+port
                  "hex_string" — match_value is a hex byte pattern, e.g. "DD" or "08 00"
                  "string"     — match_value is an ASCII string pattern
                  "u32"        — match_value is a u32 expression
    match_value : pattern for the match module (ignored for "plain")
    algo        : "bm" (Boyer-Moore) or "kmp" — for string/hex_string matches
    verdict     : "DROP", "ACCEPT", or "LOG --log-prefix ..."
    op          : "add" (append -A) or "remove" (delete -D)

    Returns: {applied, rule, input_rule, errors, elapsed_s}
    """
    t0 = time.time()
    op_flag = "-A" if op == "add" else "-D"
    base_prefix = f"iptables {op_flag} {chain} -p {protocol} --dport {dport}"

    if match_type == "hex_string":
        # Normalise: strip spaces, uppercase, re-format as space-separated pairs
        hex_val = match_value.replace(" ", "").upper()
        formatted = " ".join(hex_val[i:i + 2] for i in range(0, len(hex_val), 2))
        rule = f"{base_prefix} -m string --hex-string \"|{formatted}|\" --algo {algo} -j {verdict}"
    elif match_type == "string":
        rule = f"{base_prefix} -m string --string \"{match_value}\" --algo {algo} -j {verdict}"
    elif match_type == "u32":
        rule = f"{base_prefix} -m u32 --u32 \"{match_value}\" -j {verdict}"
    else:  # plain
        rule = f"{base_prefix} -j {verdict}"

    # Companion INPUT rule for software simulators on br0
    input_rule = rule.replace(f" {op_flag} {chain} ", f" {op_flag} INPUT ", 1)
    input_rule = input_rule if input_rule != rule else None

    errors = []
    for r in ([rule, input_rule] if input_rule else [rule]):
        rc, stderr = _run_iptables(r)
        if rc != 0:
            errors.append(f"[{r.split()[-1]}] {stderr}")

    elapsed = time.time() - t0
    applied = len(errors) == 0
    _log_patch(rule, f"{match_type} match on {protocol}/{dport}", applied, elapsed)
    return {
        "applied": applied,
        "rule": rule,
        "input_rule": input_rule,
        "errors": errors if errors else None,
        "elapsed_s": round(elapsed, 3),
    }


# ── Higher-level convenience wrappers ────────────────────────────────────────

def protocol_block(protocol: str, dport: int,
                   direction: str = "both") -> dict:
    """Block all traffic to a port with a simple DROP rule.

    direction: "forward" | "input" | "both"
    Returns: {applied, rules, errors, elapsed_s}
    """
    t0 = time.time()
    chain_map = {
        "forward": ["FORWARD"],
        "input":   ["INPUT"],
        "both":    ["FORWARD", "INPUT"],
    }
    chains = chain_map.get(direction.lower(), ["FORWARD", "INPUT"])
    rules = [f"iptables -A {c} -p {protocol} --dport {dport} -j DROP" for c in chains]

    errors = []
    for r in rules:
        rc, stderr = _run_iptables(r)
        if rc != 0:
            errors.append(f"[{r.split()[-1]}] {stderr}")

    elapsed = time.time() - t0
    applied = len(errors) == 0
    _log_patch(rules[0], f"block {protocol}/:{dport}", applied, elapsed)
    return {
        "applied": applied,
        "rules": rules,
        "errors": errors if errors else None,
        "elapsed_s": round(elapsed, 3),
    }


def modbus_fc_filter(function_code: int, dport: int = 502,
                     chain: str = "FORWARD") -> dict:
    """Drop Modbus packets containing a specific Function Code byte.

    Uses iptables u32 match on TCP payload byte offset 7 — the Modbus PDU
    function code field (skips 20-byte IP header + 20-byte TCP header +
    7-byte MBAP header = offset 47 from IP start = u32 byte 7 in the TCP
    data stream via the 0>>22&0x3C@ offset expression).

    This blocks individual Modbus function codes (e.g. FC 0x05 Write Coil)
    without blocking all Modbus traffic — more surgical than protocol_block.

    function_code: decimal FC value, e.g. 5 (Write Single Coil), 3 (Read Registers)
    Returns: {applied, rule, input_rule, function_code_hex, description, errors, elapsed_s}
    """
    t0 = time.time()
    fc_hex = f"0x{function_code:02X}"
    # Skip IP header (0>>22&0x3C bytes), skip TCP header (@), check PDU byte 7
    u32_expr = f"0>>22&0x3C@7&0xFF={fc_hex}"
    rule = (
        f"iptables -A {chain} -p tcp --dport {dport}"
        f" -m u32 --u32 \"{u32_expr}\" -j DROP"
    )
    input_rule = rule.replace(f"-A {chain} ", "-A INPUT ", 1)
    if input_rule == rule:
        input_rule = None

    errors = []
    for r in ([rule, input_rule] if input_rule else [rule]):
        rc, stderr = _run_iptables(r)
        if rc != 0:
            errors.append(f"[{r.split()[-1]}] {stderr}")

    elapsed = time.time() - t0
    applied = len(errors) == 0
    desc = f"Modbus FC {function_code} ({fc_hex}) block on TCP/{dport}"
    _log_patch(rule, desc, applied, elapsed)
    return {
        "applied": applied,
        "rule": rule,
        "input_rule": input_rule,
        "function_code_hex": fc_hex,
        "description": desc,
        "errors": errors if errors else None,
        "elapsed_s": round(elapsed, 3),
    }


def coap_rate_limit(dport: int = 5683, rate: str = "10/sec",
                    burst: int = 20, chain: str = "FORWARD") -> dict:
    """Rate-limit CoAP traffic using iptables hashlimit.

    Unlike a blanket DROP, this allows legitimate CoAP traffic while absorbing
    burst-based attacks. The hashlimit module tracks per-source-IP rates.

    rate : iptables rate string, e.g. "10/sec", "100/min"
    burst: maximum burst packet count allowed before dropping begins

    Returns: {applied, rule, input_rule, description, errors, elapsed_s}
    """
    t0 = time.time()
    name = f"coap_lim_{dport}"
    rule = (
        f"iptables -A {chain} -p udp --dport {dport}"
        f" -m hashlimit --hashlimit-name {name}"
        f" --hashlimit-above {rate} --hashlimit-burst {burst}"
        f" --hashlimit-mode srcip -j DROP"
    )
    input_rule = rule.replace(f"-A {chain} ", "-A INPUT ", 1)
    if input_rule == rule:
        input_rule = None

    errors = []
    for r in ([rule, input_rule] if input_rule else [rule]):
        rc, stderr = _run_iptables(r)
        if rc != 0:
            errors.append(f"[{r.split()[-1]}] {stderr}")

    elapsed = time.time() - t0
    applied = len(errors) == 0
    desc = f"CoAP rate-limit {rate} burst={burst} on UDP/{dport}"
    _log_patch(rule, desc, applied, elapsed)
    return {
        "applied": applied,
        "rule": rule,
        "input_rule": input_rule,
        "description": desc,
        "errors": errors if errors else None,
        "elapsed_s": round(elapsed, 3),
    }
