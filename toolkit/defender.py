"""defender.py — Virtual Patch Generator & Deployer for the Blue Agent.

Generates precision iptables rules from analyzer signatures and
applies them on the host bridge (br0) FORWARD chain to protect
OT sensors behind the gateway.
"""

import json
import subprocess
import time
from pathlib import Path

REMEDIATION_LOG = Path(__file__).resolve().parent.parent / "data" / "remediation_log.json"


def generate_iptables_rule(signature: dict) -> str:
    """Convert an analyzer signature into a precise iptables command."""
    f = signature["filter"]
    proto = f["protocol"]
    dport = f["dport"]
    direction = f.get("direction", "FORWARD")
    action = f.get("action", "DROP")

    base = f"iptables -A {direction} -p {proto} --dport {dport}"

    match_type = f.get("match")
    if match_type == "length":
        length_range = f["length_range"]
        return f"{base} -m length --length {length_range} -j {action}"
    elif match_type == "string":
        pattern = f["pattern"]
        algo = f.get("algo", "bm")
        return f"{base} -m string --string \"{pattern}\" --algo {algo} -j {action}"
    elif match_type == "u32":
        expr = f["u32_expr"]
        return f"{base} -m u32 --u32 \"{expr}\" -j {action}"
    else:
        return f"{base} -j {action}"


def apply_patch(rule: str, signature: dict, dry_run: bool = False) -> dict:
    """Apply an iptables rule on the Kali host bridge.

    Returns structured result with timing for TTP measurement.
    """
    start = time.time()
    cmd = f"sudo {rule}"

    if dry_run:
        elapsed = time.time() - start
        result = {"applied": False, "dry_run": True, "rule": rule, "elapsed_s": elapsed}
        _log_remediation(signature, result)
        return result

    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    elapsed = time.time() - start

    if proc.returncode != 0:
        result = {"applied": False, "error": proc.stderr.strip(), "rule": rule, "elapsed_s": elapsed}
    else:
        result = {"applied": True, "rule": rule, "elapsed_s": elapsed}

    _log_remediation(signature, result)
    return result


def remove_patch(rule: str) -> dict:
    """Remove an iptables rule (replace -A with -D)."""
    delete_rule = rule.replace("-A ", "-D ", 1)
    proc = subprocess.run(f"sudo {delete_rule}", shell=True,
                          capture_output=True, text=True, timeout=10)
    if proc.returncode != 0:
        return {"removed": False, "error": proc.stderr.strip(), "rule": delete_rule}
    return {"removed": True, "rule": delete_rule}


def list_forward_rules() -> list[str]:
    """List current iptables FORWARD chain rules."""
    proc = subprocess.run(
        ["sudo", "iptables", "-L", "FORWARD", "-n", "--line-numbers"],
        capture_output=True, text=True, timeout=10,
    )
    return proc.stdout.strip().splitlines()


def _log_remediation(signature: dict, result: dict) -> None:
    """Append to remediation_log.json for TTP tracking."""
    REMEDIATION_LOG.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    if REMEDIATION_LOG.exists() and REMEDIATION_LOG.stat().st_size > 0:
        entries = json.loads(REMEDIATION_LOG.read_text())
    entries.append({
        "timestamp": time.time(),
        "attack": signature.get("attack"),
        "target_ip": signature.get("target_ip"),
        "rule": result.get("rule"),
        "applied": result.get("applied"),
        "elapsed_s": result.get("elapsed_s"),
    })
    REMEDIATION_LOG.write_text(json.dumps(entries, indent=2))
