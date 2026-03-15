"""oversight.py — LLM-powered reasoning oversight layer for the APIOT agent loop.

Sits between tool execution and the next LLM call. Combines fast
deterministic guards (repetition blocking, crash/patch blocking, circuit
breaker) with an LLM reasoning layer that analyses session state and
produces intelligent steering directives.

The Overseer LLM is a *separate, cheaper* model from the main agent.
It receives a compact state snapshot and returns 2-3 concise directives.
It never makes tool calls — only the main agent does.
"""

import hashlib
import json
import logging
import os
import time

from openai import OpenAI

from apiot.core.tool_tracker import ToolTracker
from apiot.core.fingerprint import DeviceFingerprinter
from apiot.core.hooks import hooks

logger = logging.getLogger("apiot.oversight")

WINDOW_SIZE = 20
REPEAT_LIMIT = 3
STALL_THRESHOLD = 8
STALL_HARD_LIMIT = 15
STRATEGY_REFRESH_INTERVAL = 5
MAX_TURNS = 120
BLUE_TOOLS = {"analyze_attacks", "apply_patch", "verify_patch", "list_patches"}
RED_EXPLOITS = {"execute_exploit", "verify_crash", "verify_shell", "brute_force_ssh",
                "brute_force_telnet", "remote_exec", "create_tool"}

_OVERSEER_SYSTEM = """\
You are the strategic brain overseeing an autonomous IoT penetration testing \
agent. The agent MUST follow your directives — they are injected as highest-\
priority instructions. You receive a snapshot of the agent's session state \
and must provide exactly 2-3 concise, IMMEDIATELY ACTIONABLE directives.

Rules:
- Each directive must start with a specific tool call the agent should make. \
  Format: "Use `tool_name` on IP with params..." — the agent needs to know \
  EXACTLY what to call.
- Reference the failure history — do NOT suggest things that already failed \
  unless you have a concrete variation (different port, different creds, \
  different payload).
- PRIORITIZE DIVERSITY: if the agent has only used brute_force_ssh, direct \
  it to different attack classes (OT exploits, CoAP, Modbus, HTTP injection, \
  create_tool for custom exploits, run_command for protocol-specific probing).
- If the agent is repeating the same approach, EXPLICITLY tell it to stop \
  and name the specific alternative tool+target+port.
- If phase transition is appropriate, say so explicitly.
- Keep your response under 150 words. No preamble, no markdown headers, \
  just numbered directives starting with 1."""


def _hash_call(tool: str, ip: str, args: dict) -> str:
    """Deterministic hash of a tool call for dedup."""
    key = f"{tool}:{ip}:{json.dumps(args, sort_keys=True, default=str)}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


class Overseer:
    """Middleware brain that evaluates progress and steers the agent."""

    def __init__(self, memory, session_id: str | None = None):
        self.memory = memory
        self.session_id = session_id
        self.tracker = ToolTracker(memory) if memory else None
        self.fingerprinter = DeviceFingerprinter(memory) if memory else None

        self.turn = 0
        self.last_progress_turn = 0
        self.call_window: list[tuple[str, str, str]] = []  # (tool, ip, hash)
        self.fail_counts: dict[str, int] = {}  # "tool:ip" -> consecutive fails
        self.targets_attempted: set[str] = set()
        self.targets_compromised: set[str] = set()
        self.targets_total: int = 0
        self.phase = "red"
        self.vuln_count = 0
        self.patch_count = 0
        self.verified_count = 0
        self._pending_steering: list[dict] = []
        self._last_refresh_turn = 0

        self._overseer_model = os.environ.get("OVERSEER_MODEL", "openai/gpt-4o-mini")
        self._overseer_enabled = os.environ.get("OVERSEER_ENABLED", "true").lower() == "true"
        self._llm_client: OpenAI | None = None
        self._pending_flag: str | None = None  # EXT4: steering type to attach to next tool call

    def _get_llm_client(self) -> OpenAI | None:
        """Lazy-init the Overseer's own LLM client."""
        if self._llm_client is not None:
            return self._llm_client
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            return None
        self._llm_client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            default_headers={
                "HTTP-Referer": "https://github.com/Adelsamir01/apiot",
                "X-Title": "APIOT Overseer",
            },
        )
        return self._llm_client

    # ── LLM reasoning core ───────────────────────────────────────────

    def _build_state_snapshot(self, trigger: str, extra: str = "") -> str:
        """Build a compact state summary for the Overseer LLM."""
        lines = [
            f"Trigger: {trigger}",
            f"Turn: {self.turn}, Phase: {self.phase}",
            f"Targets: {len(self.targets_attempted)}/{max(self.targets_total, len(self.targets_attempted))} attempted, "
            f"{len(self.targets_compromised)} compromised",
            f"Findings: {self.vuln_count} vulns, {self.patch_count} patches, {self.verified_count} verified",
            f"Turns since last progress: {self.turn - self.last_progress_turn}",
        ]

        if self.call_window:
            lines.append("\nRecent tool calls (last 5):")
            for tool, ip, h in self.call_window[-5:]:
                fail_key = f"{tool}:{ip}"
                fc = self.fail_counts.get(fail_key, 0)
                status = f"({fc} consecutive fails)" if fc else "(ok)"
                lines.append(f"  - {tool}({ip}) {status}")

        high_fail = [(k, v) for k, v in self.fail_counts.items() if v >= 2]
        if high_fail:
            lines.append("\nHigh-failure targets:")
            for key, count in sorted(high_fail, key=lambda x: -x[1])[:5]:
                lines.append(f"  - {key}: {count} failures")

        if self.memory:
            profiles = self.memory.get_all_device_profiles()
            if profiles:
                lines.append("\nDevice profiles:")
                for p in profiles[:8]:
                    ip = p.get("ip", "?")
                    status = p.get("status", "unknown")
                    services = (p.get("services_json") or "")[:80]
                    attempted = "attempted" if ip in self.targets_attempted else "not attempted"
                    compromised = ", compromised" if ip in self.targets_compromised else ""
                    lines.append(f"  - {ip}: status={status}, {attempted}{compromised}, services={services}")

            try:
                from apiot.core.strategy import get_untried_attacks
                for p in profiles[:8]:
                    ip = p.get("ip", "?")
                    untried = get_untried_attacks(self.memory, ip, p)
                    if untried:
                        lines.append(f"  Untried attacks for {ip}: {', '.join(untried[:6])}")
            except Exception:
                pass

        if self.tracker:
            ctx = self.tracker.build_tool_context()
            if "No tool" not in ctx:
                lines.append(f"\nTool effectiveness:\n{ctx}")

        exploit_tools = [t for t, _, _ in self.call_window if t in RED_EXPLOITS]
        if exploit_tools:
            from collections import Counter
            counts = Counter(exploit_tools)
            total = len(exploit_tools)
            dominant = counts.most_common(1)[0]
            if dominant[1] / total > 0.6:
                lines.append(
                    f"\nWARNING — LOW DIVERSITY: {dominant[1]}/{total} recent exploit calls "
                    f"used '{dominant[0]}'. The agent is over-relying on a single tool. "
                    f"Direct it to use DIFFERENT attack classes."
                )

        if extra:
            lines.append(f"\nAdditional context: {extra}")

        return "\n".join(lines)

    def _call_overseer_llm(self, trigger: str, extra: str = "") -> str | None:
        """Call the Overseer LLM for intelligent reasoning. Returns directive text or None."""
        if not self._overseer_enabled:
            return None

        client = self._get_llm_client()
        if not client:
            return None

        snapshot = self._build_state_snapshot(trigger, extra)
        logger.info("Overseer LLM call: trigger=%s, snapshot_len=%d", trigger, len(snapshot))

        try:
            t0 = time.time()
            resp = client.chat.completions.create(
                model=self._overseer_model,
                messages=[
                    {"role": "system", "content": _OVERSEER_SYSTEM},
                    {"role": "user", "content": snapshot},
                ],
                max_tokens=300,
                temperature=0.3,
                timeout=15,
            )
            elapsed = time.time() - t0
            content = (resp.choices[0].message.content or "").strip()
            logger.info("Overseer LLM responded in %.1fs (%d chars)", elapsed, len(content))
            hooks.emit("overseer.llm_call", {
                "trigger": trigger, "elapsed": elapsed,
                "response_len": len(content),
            })
            return content if content else None
        except Exception as e:
            logger.warning("Overseer LLM call failed (%s): %s", trigger, e)
            return None

    # ── Pre-dispatch: should we block this call? ──────────────────────

    def check_tool_call(self, tool: str, args: dict) -> tuple[bool, str, str]:
        """Check if a tool call should be blocked.

        Returns (blocked: bool, reason: str, overseer_flag: str).
        Deterministic — no LLM calls here for speed.

        overseer_flag values:
          'none'            — call allowed, no intervention
          'blocked_repeat'  — repetition guard blocked this call
          'blocked_crashed' — target already crashed
          'blocked_patched' — attack already has verified patch
          'stall_steer'     — stall steering was injected before this turn
          'phase_enforce'   — phase transition was enforced before this turn
          'strategy_refresh'— strategy refresh was injected before this turn
          'disabled'        — overseer is disabled (set by agent, not here)
        """
        ip = args.get("ip", args.get("target_ip", ""))
        call_hash = _hash_call(tool, ip, args)

        count = sum(1 for t, i, h in self.call_window if h == call_hash)
        if count >= REPEAT_LIMIT:
            reason = (
                f"BLOCKED: Identical call {tool}({ip}) repeated {count} times. "
                f"Try a different tool, different parameters, or a different target."
            )
            logger.info(reason)
            self._pending_flag = None
            return True, reason, "blocked_repeat"

        if ip and self.memory:
            profile = self.memory.get_device_profile(ip)
            if profile and profile.get("status") == "crashed" and tool in RED_EXPLOITS:
                reason = f"BLOCKED: Target {ip} is already crashed. Move to another target."
                self._pending_flag = None
                return True, reason, "blocked_crashed"

            if tool == "execute_exploit":
                attack = args.get("tool_name", "")
                if attack and self.memory.is_already_patched(ip, attack):
                    reason = (
                        f"BLOCKED: Attack '{attack}' on {ip} already has a verified patch. "
                        f"Try a different attack vector."
                    )
                    self._pending_flag = None
                    return True, reason, "blocked_patched"

        # Call allowed — attach any pending steering flag
        flag = self._pending_flag or "none"
        self._pending_flag = None
        return False, "", flag

    # ── Post-dispatch: evaluate result and enrich ─────────────────────

    def evaluate_result(self, tool: str, args: dict, result_json: str,
                        success: bool) -> str:
        """Evaluate a tool result. Returns enriched result string."""
        ip = args.get("ip", args.get("target_ip", ""))
        call_hash = _hash_call(tool, ip, args)
        self.turn += 1

        self.call_window.append((tool, ip, call_hash))
        if len(self.call_window) > WINDOW_SIZE:
            self.call_window = self.call_window[-WINDOW_SIZE:]

        if ip:
            self.targets_attempted.add(ip)

        fail_key = f"{tool}:{ip}"
        if success:
            self.fail_counts.pop(fail_key, None)
            self.last_progress_turn = self.turn
            if tool == "verify_crash":
                self.vuln_count += 1
                if ip and self.fingerprinter:
                    self.fingerprinter.update_from_exploit(ip, tool, {"success": True})
            elif tool == "verify_shell":
                self.vuln_count += 1
                if ip:
                    self.targets_compromised.add(ip)
                    if self.fingerprinter:
                        self.fingerprinter.update_from_exploit(
                            ip, tool, {"success": True, "credential": args.get("creds", "")})
            elif tool == "verify_patch":
                self.patch_count += 1
                self.verified_count += 1
            elif tool == "apply_patch":
                self.patch_count += 1
        else:
            if tool in RED_EXPLOITS:
                self.fail_counts[fail_key] = self.fail_counts.get(fail_key, 0) + 1

        if tool in BLUE_TOOLS:
            self.phase = "blue"

        progress = (
            f"\n[Progress: turn {self.turn}, "
            f"{self.vuln_count} vulns, {self.patch_count} patches, "
            f"{len(self.targets_attempted)}/{max(self.targets_total, len(self.targets_attempted))} targets, "
            f"phase={self.phase}]"
        )

        enriched = result_json
        if not success and tool in RED_EXPLOITS and ip:
            fc = self.fail_counts.get(fail_key, 0)
            if fc >= 2:
                hint = self._get_alternative_hint(ip, tool)
                if hint:
                    enriched += f"\n[OVERSEER ANALYSIS: {hint}]"

        return enriched + progress

    # ── Inter-turn: generate steering messages ────────────────────────

    def get_steering_messages(self) -> list[dict]:
        """Return steering messages to inject before the next LLM call."""
        msgs = list(self._pending_steering)
        self._pending_steering.clear()

        self._check_diversity(msgs)
        self._check_stall(msgs)
        self._check_phase_transition(msgs)
        self._check_strategy_refresh(msgs)
        self._check_circuit_breaker(msgs)

        return msgs

    def _check_diversity(self, msgs: list[dict]):
        if self.turn < 6 or self.phase != "red":
            return
        recent_exploits = [(t, ip) for t, ip, _ in self.call_window[-10:] if t in RED_EXPLOITS]
        if len(recent_exploits) < 4:
            return
        tools_used = [t for t, _ in recent_exploits]
        from collections import Counter
        counts = Counter(tools_used)
        dominant_tool, dominant_count = counts.most_common(1)[0]
        if dominant_count / len(recent_exploits) < 0.7:
            return
        unique_ips = {ip for _, ip in recent_exploits}
        if len(unique_ips) <= 1:
            return
        analysis = self._call_overseer_llm(
            "diversity_alert",
            f"The agent has used '{dominant_tool}' for {dominant_count}/{len(recent_exploits)} "
            f"of its recent exploit calls across {len(unique_ips)} different targets. "
            f"This is monotonic behavior. Direct it to use fundamentally different tools "
            f"(OT exploits, CoAP, Modbus, HTTP injection, create_tool, run_command).",
        )
        if analysis:
            msgs.append({"role": "user", "content": self._wrap_directive(analysis)})
        else:
            msgs.append({"role": "user", "content": self._wrap_directive(
                f"STOP using {dominant_tool} repeatedly. You have used it {dominant_count} times "
                f"in your last {len(recent_exploits)} exploit calls. Use DIFFERENT attack tools: "
                f"try execute_exploit with coap_option_overflow, modbus_write_coil, "
                f"http_cmd_injection, or use create_tool to build a custom exploit."
            )})

    def _check_stall(self, msgs: list[dict]):
        gap = self.turn - self.last_progress_turn
        if gap >= STALL_HARD_LIMIT and self.phase == "red":
            analysis = self._call_overseer_llm(
                "stall_hard_limit",
                f"Agent has made ZERO progress in {gap} turns. "
                f"This is critical — the agent must either find a new approach or stop.",
            )
            directive = analysis or "Transition to blue team phase NOW, or output TASK_COMPLETE if no findings."
            msgs.append({"role": "user", "content": self._wrap_directive(directive)})
            self._pending_flag = "stall_steer"  # EXT4: tag next tool call
            hooks.emit("phase.red_complete", {"reason": "stall_hard_limit", "turn": self.turn})
        elif gap >= STALL_THRESHOLD:
            analysis = self._call_overseer_llm(
                "stall_detected",
                f"No new findings in {gap} turns. The agent needs to change approach.",
            )
            directive = analysis or self._build_stall_hint_heuristic()
            msgs.append({"role": "user", "content": self._wrap_directive(
                f"No new findings in {gap} turns. {directive}")})
            self._pending_flag = "stall_steer"  # EXT4: tag next tool call

    def _check_phase_transition(self, msgs: list[dict]):
        if self.phase != "red":
            return
        if not self.targets_total:
            return
        if len(self.targets_attempted) >= self.targets_total and self.vuln_count > 0:
            analysis = self._call_overseer_llm(
                "phase_transition",
                f"All {self.targets_total} targets attempted, {self.vuln_count} vulns found. "
                f"Should the agent switch to blue team or continue red team on unexplored vectors?",
            )
            if analysis and "continue" in analysis.lower() and "red" in analysis.lower():
                msgs.append({"role": "user", "content": self._wrap_directive(analysis)})
                return
            self.phase = "blue"
            hooks.emit("phase.red_complete", {"vulns": self.vuln_count, "turn": self.turn})
            directive = analysis or (
                f"All {self.targets_total} targets attempted. "
                f"{self.vuln_count} vulnerabilities found. "
                f"Begin BLUE TEAM phase: call analyze_attacks, then apply_patch and verify_patch for each."
            )
            msgs.append({"role": "user", "content": self._wrap_directive(directive)})
            self._pending_flag = "phase_enforce"  # EXT4: tag next tool call

    def _check_strategy_refresh(self, msgs: list[dict]):
        if self.turn - self._last_refresh_turn < STRATEGY_REFRESH_INTERVAL:
            return
        self._last_refresh_turn = self.turn

        analysis = self._call_overseer_llm("strategy_refresh")
        if analysis:
            msgs.append({"role": "user", "content": self._wrap_directive(analysis)})
            self._pending_flag = "strategy_refresh"  # EXT4: tag next tool call
            return

        if not self.memory:
            return
        parts = [f"[OVERSEER STATUS] Turn {self.turn}, phase={self.phase}"]
        if self.tracker:
            ctx = self.tracker.build_tool_context()
            if "No tool" not in ctx:
                parts.append(ctx)
        from apiot.core.strategy import build_mission_strategy
        strat = build_mission_strategy(self.memory)
        if strat and "No known" not in strat:
            parts.append(strat[:500])
        parts.append(
            f"Targets: {len(self.targets_attempted)}/{max(self.targets_total, len(self.targets_attempted))} attempted, "
            f"{len(self.targets_compromised)} compromised | "
            f"Findings: {self.vuln_count} vulns, {self.patch_count} patches, {self.verified_count} verified"
        )
        msgs.append({"role": "user", "content": "\n".join(parts)})
        self._pending_flag = "strategy_refresh"  # EXT4: tag next tool call

    def _check_circuit_breaker(self, msgs: list[dict]):
        if self.turn >= MAX_TURNS:
            msgs.append({"role": "user", "content": (
                f"[OVERSEER] Turn limit ({MAX_TURNS}) reached. "
                f"Wrap up and output TASK_COMPLETE now."
            )})

    # ── Helpers ───────────────────────────────────────────────────────

    def _get_alternative_hint(self, ip: str, failed_tool: str = "") -> str:
        """Get an intelligent alternative when attacks fail on a target."""
        extra = f"Tool '{failed_tool}' just failed on {ip} for the {self.fail_counts.get(f'{failed_tool}:{ip}', 0)}th time."
        analysis = self._call_overseer_llm("failure_analysis", extra)
        if analysis:
            return analysis

        return self._get_alternative_hint_heuristic(ip)

    def _get_alternative_hint_heuristic(self, ip: str) -> str:
        """Deterministic fallback for alternative hints."""
        if not self.memory:
            return ""
        try:
            from apiot.core.strategy import get_untried_attacks
            profile = self.memory.get_device_profile(ip)
            if not profile:
                return "Consider using run_command for manual recon."
            untried = get_untried_attacks(self.memory, ip, profile)
            if untried:
                return f"Untried vectors for {ip}: {', '.join(untried[:4])}. Consider create_tool or run_command."
            return "All known vectors tried. Use create_tool for a custom exploit or run_command for manual probing."
        except Exception:
            return ""

    def _build_stall_hint_heuristic(self) -> str:
        """Deterministic fallback for stall hints."""
        parts = []
        if self.memory:
            profiles = self.memory.get_all_device_profiles()
            unattempted = [p["ip"] for p in profiles if p["ip"] not in self.targets_attempted]
            if unattempted:
                parts.append(f"Unattempted targets: {', '.join(unattempted[:5])}")

        high_fail = [k for k, v in self.fail_counts.items() if v >= 2]
        if high_fail:
            parts.append(f"Repeated failures on: {', '.join(high_fail[:3])} — try different tools")

        if not parts:
            parts.append("Consider: run_command for nmap deep scan, or create_tool for custom exploits")
        return " | ".join(parts)

    def _wrap_directive(self, content: str) -> str:
        """Wrap a directive so the agent treats it as a mandatory instruction."""
        return (
            f"[OVERSEER — MANDATORY DIRECTIVE] You MUST follow these instructions "
            f"as your NEXT action. Do NOT ignore this and continue with your own plan.\n\n"
            f"{content}"
        )

    def set_target_count(self, count: int):
        self.targets_total = count
