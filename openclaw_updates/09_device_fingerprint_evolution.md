# 09 — Device Fingerprint Evolution

## Problem

The network mapper runs once at startup and produces a static snapshot. If a device changes state (comes online, crashes, gets patched, reveals new services), the agent doesn't know. The classifier uses simple heuristics (port open/closed) and never updates. There is no concept of a device's profile evolving over time.

## What OpenClaw Does

OpenClaw's memory system uses content-hash-based change detection and incremental sync. When files change, only the delta is re-indexed. The temporal decay system ensures recent observations are weighted higher than stale ones.

## How APIOT Should Implement This

### Living Device Profiles

Instead of a flat `network_state.json` snapshot, device profiles should be living documents that accumulate observations:

```python
class DeviceProfile:
    ip: str
    firmware_id: str
    arch: str
    first_seen: float          # timestamp
    last_seen: float           # timestamp
    
    # Evolving observations
    services: dict[int, ServiceObservation]  # port -> latest observation
    credentials: list[Credential]            # all discovered creds
    vulnerabilities: list[Finding]           # all findings
    patches: list[Patch]                     # applied patches
    
    # Attack history
    attack_count: int
    last_attack: float
    successful_attacks: list[str]  # tool names that worked
    failed_attacks: list[str]      # tool names that failed
    
    # Behavioral observations
    crash_count: int               # how many times it's been crashed
    recovery_observed: bool        # did it come back after a crash?
    response_time_ms: float        # average response latency
```

### Incremental Fingerprinting

Instead of running the full mapper every session, add an `update_fingerprint` tool the agent can use to re-scan a specific device:

```python
def cmd_update_fingerprint(ip: str, interface: str = None) -> dict:
    """Re-scan a single device and update its profile."""
    # Detect which interface to use based on IP range
    if interface is None:
        interface = "br_internal" if ip.startswith("192.168.200.") else "br0"
    
    fp = fingerprint_target(ip, ports=SCAN_PORTS, timing="T4", interface=interface)
    udp = udp_probe(ip, ports=UDP_PORTS, timing="T4", interface=interface)
    
    # Merge UDP results
    for port, info in udp["ports"].items():
        if info["state"] in ("open", "open|filtered"):
            fp["ports"][port] = info
    
    # Classify and update profile
    open_ports = {int(p) for p, info in fp["ports"].items() 
                  if info["state"] in ("open", "open|filtered")}
    tag = classify(open_ports, None)
    fp["classification"] = tag
    
    # Compare with previous profile and note changes
    memory = MemoryStore()
    prev = memory.get_device_profile(ip)
    changes = detect_changes(prev, fp)
    
    # Update profile
    memory.update_device_profile(ip, fp, changes)
    
    return {"fingerprint": fp, "changes": changes}
```

### Change Detection

```python
def detect_changes(prev_profile, new_fp):
    """Detect what changed since last observation."""
    changes = []
    if prev_profile is None:
        return [{"type": "new_device", "ip": new_fp["ip"]}]
    
    prev_ports = set(prev_profile.get("open_ports", []))
    new_ports = {int(p) for p, info in new_fp["ports"].items() 
                 if info["state"] in ("open", "open|filtered")}
    
    for port in new_ports - prev_ports:
        changes.append({"type": "new_port", "port": port})
    for port in prev_ports - new_ports:
        changes.append({"type": "closed_port", "port": port})
    
    return changes
```

### Agent Awareness

The agent should be instructed to re-fingerprint devices at key moments:
- After applying a patch (to verify the patch didn't open new ports)
- After crashing a device and waiting for recovery
- When starting a new session (quick health check)
- When lateral movement reveals new information about a device

## Files to Modify

- `core/agent_loop.py` — add `cmd_update_fingerprint`
- `core/tools/registry.py` — add `update_fingerprint` tool schema
- `core/tools/dispatcher.py` — dispatch `update_fingerprint`
- Depends on: `01_persistent_memory.md`

## Estimated Effort

Small-medium. The fingerprinting logic already exists in the mapper; this wraps it for single-device use and adds change detection.

## Implementation Notes

Executed. Files created:
- `core/fingerprint.py` — `DeviceFingerprinter` class with update_from_scan, update_from_exploit, update_from_remote_exec, get_device_summary, get_all_summaries. Incrementally builds profiles from multiple data sources, detects service/firmware changes.
