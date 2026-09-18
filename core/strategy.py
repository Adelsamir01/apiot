"""strategy.py — Novel exploitation strategy engine.

Generates structured exploitation plans based on device profiles,
prior attack history, and available tools. Prevents repetitive attacks
by tracking what has been tried and focusing on unexplored vectors.
"""

from apiot.core.memory_store import MemoryStore


KNOWLEDGE_BLOCKS = {
    "openwrt_gateway": {
        "common_vulns": ["default_creds_ssh", "default_creds_http", "ubus_unauthenticated", "luci_rce"],
        "post_exploit": ["enumerate_routes", "arp_table", "iptables_dump", "proc_version", "uci_show"],
        "lateral": ["arp_scan_internal", "ssh_to_downstream", "dhcp_lease_dump"],
        "persistence": ["crontab_backdoor", "rc_local_hook", "ssh_key_injection"],
    },
    "embedded_linux": {
        "common_vulns": ["telnet_default", "busybox_overflow", "httpd_cgi_injection"],
        "post_exploit": ["ps_aux", "netstat_listen", "cat_etc_passwd", "mount_rw"],
        "lateral": ["arp_neighbors", "udp_discovery"],
        "persistence": ["init_script_hook", "firmware_mod"],
    },
    "iot_sensor": {
        "common_vulns": ["mqtt_unauth", "coap_unauth", "default_web_panel"],
        "post_exploit": ["sensor_data_read", "config_dump", "firmware_version"],
        "lateral": ["zigbee_scan", "ble_scan"],
        "persistence": ["ota_intercept"],
    },
}


def classify_device(profile: dict) -> str:
    """Classify a device profile into a knowledge category."""
    services = profile.get("services_json", "") or ""
    name = (profile.get("device_name") or profile.get("firmware_id") or "").lower()
    if "openwrt" in name or "luci" in services.lower():
        return "openwrt_gateway"
    if "mqtt" in services.lower() or "coap" in services.lower():
        return "iot_sensor"
    return "embedded_linux"


def get_untried_attacks(memory: MemoryStore, ip: str, profile: dict) -> list[str]:
    """Return attack vectors that haven't been tried on this device."""
    category = classify_device(profile)
    kb = KNOWLEDGE_BLOCKS.get(category, KNOWLEDGE_BLOCKS["embedded_linux"])
    all_attacks = kb["common_vulns"] + kb["post_exploit"] + kb["lateral"]

    history = memory.get_tool_history_for_device(ip, limit=200)
    tried = {h.get("tool_name", "") for h in history}
    tried |= {h.get("result_summary", "") for h in history if h.get("success")}

    return [a for a in all_attacks if a not in tried]


def build_attack_plan(memory: MemoryStore, ip: str, profile: dict) -> dict:
    """Build a structured exploitation plan for a device."""
    category = classify_device(profile)
    kb = KNOWLEDGE_BLOCKS.get(category, KNOWLEDGE_BLOCKS["embedded_linux"])
    untried = get_untried_attacks(memory, ip, profile)
    patches = memory.get_patches_for_device(ip)
    patched_attacks = {p["attack_name"] for p in patches if p.get("verified")}

    plan = {
        "ip": ip,
        "category": category,
        "untried_attacks": [a for a in untried if a not in patched_attacks],
        "post_exploit_ideas": kb["post_exploit"],
        "lateral_movement": kb["lateral"],
        "persistence_options": kb["persistence"],
        "already_patched": list(patched_attacks),
        "recommendation": "",
    }

    if plan["untried_attacks"]:
        plan["recommendation"] = (
            f"Try these unexplored vectors: {', '.join(plan['untried_attacks'][:5])}. "
            f"After gaining access, explore post-exploitation: {', '.join(kb['post_exploit'][:3])}."
        )
    elif not patched_attacks:
        plan["recommendation"] = (
            "All standard attacks tried. Use create_tool to write custom exploits, "
            "or use remote_exec for deeper post-exploitation enumeration."
        )
    else:
        plan["recommendation"] = (
            f"Device has {len(patched_attacks)} verified patches. "
            "Focus on bypassing existing defenses or testing patch effectiveness."
        )

    return plan


def build_mission_strategy(memory: MemoryStore, target_ips: list[str] | None = None) -> str:
    """Build a full strategy prompt segment for a set of targets."""
    profiles = memory.get_all_device_profiles()
    if target_ips:
        profiles = [p for p in profiles if p["ip"] in target_ips]

    if not profiles:
        return "No known device profiles. Start with network scanning to discover targets."

    parts = ["=== Attack Strategy ===\n"]
    for p in profiles:
        plan = build_attack_plan(memory, p["ip"], p)
        parts.append(f"Target: {p['ip']} ({plan['category']})")
        parts.append(f"  Recommendation: {plan['recommendation']}")
        if plan["untried_attacks"]:
            parts.append(f"  Untried: {', '.join(plan['untried_attacks'][:8])}")
        if plan["already_patched"]:
            parts.append(f"  Patched: {', '.join(plan['already_patched'])}")
        parts.append("")

    parts.append("=== End Strategy ===")
    return "\n".join(parts)
