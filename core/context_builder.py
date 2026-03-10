"""context_builder.py — Builds session context from persistent memory.

Generates a structured context block injected into the agent's conversation
at session start, giving it awareness of past sessions, known devices,
findings, patches, and attack history.
"""

from apiot.core.memory_store import MemoryStore


def build_mission_context(memory: MemoryStore, target_ips: list[str] | None = None,
                          mode: str = "full_purple") -> str:
    """Build a context injection string from persistent memory.

    Args:
        memory: The memory store instance.
        target_ips: If set, focus context on these specific IPs.
        mode: Mission mode (full_purple, targeted_red, novel, blue_only, recon).

    Returns:
        A formatted string to inject as the first user message.
    """
    parts = ["=== APIOT Mission Context ===\n"]

    # Session history summary
    sessions = memory.get_session_history(limit=5)
    if sessions:
        parts.append(f"Prior sessions: {len(sessions)}")
        for s in sessions[-3:]:
            outcome = s.get("outcome", "?")
            vulns = s.get("vulns_found", 0)
            patches = s.get("patches_applied", 0)
            parts.append(f"  - Session {s['id'][:8]}: {outcome}, {vulns} vulns, {patches} patches")
        parts.append("")

    # Device profiles
    profiles = memory.get_all_device_profiles()
    if profiles:
        parts.append("Known devices:")
        for p in profiles:
            ip = p["ip"]
            if target_ips and ip not in target_ips:
                continue
            name = p.get("device_name") or p.get("firmware_id") or "unknown"
            status = p.get("status", "unknown")
            creds = p.get("known_creds", "")
            parts.append(f"  {ip} ({name}) — status: {status}")
            if creds:
                parts.append(f"    Known creds: {creds}")

            # Findings for this device
            findings = memory.get_findings_for_device(ip)
            if findings:
                for f in findings[-5:]:
                    ft = f.get("finding_type", "?")
                    tool = f.get("tool_used", "?")
                    st = f.get("status", "open")
                    parts.append(f"    Finding: {ft} via {tool} [{st}]")

            # Patches for this device
            patches = memory.get_patches_for_device(ip)
            if patches:
                for pat in patches:
                    atk = pat.get("attack_name", "?")
                    verified = "verified" if pat.get("verified") else "unverified"
                    parts.append(f"    Patch: {atk} [{verified}]")

            # Past tool calls
            if target_ips and ip in target_ips:
                history = memory.get_tool_history_for_device(ip, limit=10)
                if history:
                    parts.append(f"    Attack history (last {len(history)}):")
                    for h in history:
                        tool = h.get("tool_name", "?")
                        ok = "OK" if h.get("success") else "FAIL"
                        parts.append(f"      - {tool}: {ok}")
        parts.append("")

    # Open findings summary
    open_findings = memory.get_open_findings()
    if open_findings:
        parts.append(f"Open vulnerabilities: {len(open_findings)}")
        for f in open_findings[:10]:
            parts.append(f"  - {f['ip']}: {f['finding_type']} via {f['tool_used']}")
        parts.append("")

    # Active patches summary
    active_patches = memory.get_active_patches()
    if active_patches:
        parts.append(f"Active patches: {len(active_patches)}")
        for p in active_patches[:10]:
            v = "VERIFIED" if p.get("verified") else "unverified"
            parts.append(f"  - {p['ip']}: {p['attack_name']} [{v}]")
        parts.append("")

    # Mode-specific instructions
    if mode == "novel":
        parts.append("INSTRUCTION: You have already tested these devices with standard tools.")
        parts.append("Do NOT repeat attacks that already succeeded. Focus on:")
        parts.append("  - Post-exploitation on compromised hosts (use remote_exec)")
        parts.append("  - Service discovery and enumeration via run_command")
        parts.append("  - Custom exploits via create_tool")
        parts.append("  - Lateral movement through multi-homed gateways")
    elif mode == "blue_only":
        parts.append("INSTRUCTION: Skip red team. Go directly to blue team phase.")
        parts.append("Analyze existing findings, apply patches, and verify them.")
    elif mode == "recon":
        parts.append("INSTRUCTION: Reconnaissance only. Scan and enumerate.")
        parts.append("Do NOT exploit any targets. Map services, fingerprint devices.")
    elif mode == "targeted_red":
        if target_ips:
            parts.append(f"INSTRUCTION: Focus ONLY on: {', '.join(target_ips)}")
            parts.append("Test all available attack vectors on these targets.")
    else:
        if open_findings:
            parts.append("INSTRUCTION: Prioritize devices with open (unpatched) vulnerabilities.")
            parts.append("Skip re-exploiting devices where patches are already VERIFIED.")

    parts.append("\n=== End Context ===")
    return "\n".join(parts)
