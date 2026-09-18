"""fingerprint.py — Device fingerprint evolution and change detection.

Incrementally builds and updates device profiles from scan results,
tool outputs, and exploitation results. Detects changes in services,
firmware, and device state over time.
"""

import json
import time
from apiot.core.memory_store import MemoryStore


class DeviceFingerprinter:
    """Manages device profile evolution from scan and exploitation data."""

    def __init__(self, memory: MemoryStore):
        self.memory = memory

    def update_from_scan(self, ip: str, scan_data: dict) -> dict:
        """Update device profile from network scan results.

        Args:
            ip: Device IP.
            scan_data: Dict with keys like ports, os_hint, hostname, etc.

        Returns:
            Dict with 'changes' list describing what changed.
        """
        existing = self.memory.get_device_profile(ip)
        changes = []

        services_new = json.dumps(scan_data.get("ports", []))
        name = scan_data.get("hostname") or scan_data.get("os_hint")
        firmware = scan_data.get("firmware_id")
        arch = scan_data.get("arch")

        if existing:
            old_services = existing.get("services_json", "")
            if old_services and old_services != services_new:
                changes.append(f"services changed: {old_services} -> {services_new}")
            if firmware and existing.get("firmware_id") != firmware:
                changes.append(f"firmware changed: {existing.get('firmware_id')} -> {firmware}")
        else:
            changes.append("new device discovered")

        self.memory.upsert_device_profile(
            ip,
            firmware_id=firmware,
            arch=arch,
            device_name=name,
            services=services_new,
            status="discovered",
        )
        return {"ip": ip, "changes": changes, "is_new": existing is None}

    def update_from_exploit(self, ip: str, tool_name: str, result: dict) -> dict:
        """Update device profile based on exploitation results.

        Args:
            ip: Target IP.
            tool_name: The exploit tool used.
            result: The exploitation result dict.

        Returns:
            Dict with updates applied.
        """
        updates = {}

        if result.get("success") or result.get("credential"):
            cred = result.get("credential", "")
            if cred:
                updates["known_creds"] = cred
            updates["status"] = "compromised"

        if updates:
            self.memory.upsert_device_profile(ip, **updates)

        return {"ip": ip, "updates": updates}

    def update_from_remote_exec(self, ip: str, command: str, output: str) -> dict:
        """Extract fingerprint info from remote command execution output.

        Args:
            ip: Target IP.
            command: Command that was executed.
            output: stdout from the command.

        Returns:
            Dict with extracted data.
        """
        extracted = {}

        if "uname" in command.lower():
            lines = output.strip().split("\n")
            if lines:
                arch = lines[0].split()[-1] if lines[0] else None
                if arch:
                    extracted["arch"] = arch
                    self.memory.upsert_device_profile(ip, arch=arch)

        if "cat /etc/openwrt_release" in command or "cat /etc/os-release" in command:
            for line in output.strip().split("\n"):
                if "DISTRIB_ID" in line or "ID=" in line:
                    val = line.split("=", 1)[-1].strip().strip("'\"")
                    extracted["os"] = val
                    self.memory.upsert_device_profile(ip, device_name=val)

        return {"ip": ip, "extracted": extracted}

    def get_device_summary(self, ip: str) -> str:
        """Get a human-readable summary of a device's current profile."""
        p = self.memory.get_device_profile(ip)
        if not p:
            return f"{ip}: Unknown device (not yet scanned)"

        parts = [f"{ip}:"]
        if p.get("device_name"):
            parts.append(f"name={p['device_name']}")
        if p.get("firmware_id"):
            parts.append(f"fw={p['firmware_id']}")
        if p.get("arch"):
            parts.append(f"arch={p['arch']}")
        if p.get("known_creds"):
            parts.append(f"creds={p['known_creds']}")
        parts.append(f"status={p.get('status', 'unknown')}")

        findings = self.memory.get_findings_for_device(ip)
        patches = self.memory.get_patches_for_device(ip)
        if findings:
            parts.append(f"findings={len(findings)}")
        if patches:
            parts.append(f"patches={len(patches)}")

        return " ".join(parts)

    def get_all_summaries(self) -> str:
        """Get summaries of all known devices."""
        profiles = self.memory.get_all_device_profiles()
        if not profiles:
            return "No known devices."
        return "\n".join(self.get_device_summary(p["ip"]) for p in profiles)
