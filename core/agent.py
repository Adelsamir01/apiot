"""agent.py — The autonomous APIOT daemon loop (Agent Brain).

Maintains conversational context, submits tool schemas to OpenRouter,
and dispatches tool calls to the local APIOT toolkit.

All agent activity is printed sequentially to the terminal and logged
to data/logs/session_<timestamp>.log.
"""

import json
import os
import sys
import threading
import time
from pathlib import Path
from openai import OpenAI
from apiot.core import config
from apiot.core.state import AgentMemory
from apiot.core.tools.registry import TOOL_SCHEMAS
from apiot.core.tools.dispatcher import dispatch_tool
from apiot.core.tui import OperatorConsole
from apiot.core.compaction import (
    estimate_tokens,
    compact_messages,
    get_context_budget,
    truncate_result_for_history,
)
from apiot.core.hooks import hooks
from apiot.core.oversight import Overseer


SYSTEM_PROMPT = """\
You are APIOT, an autonomous Purple Team security agent operating against a virtual IoT lab.

CRITICAL — Overseer directives:
- Messages prefixed with [OVERSEER] come from your oversight system — a senior analyst \
  that monitors your progress and decides strategy.
- You MUST follow [OVERSEER] directives. They are your HIGHEST PRIORITY instructions.
- When an [OVERSEER] message tells you to use a specific tool, target, or approach, \
  your very next action MUST execute that directive. Do NOT ignore it and continue \
  with your own plan.
- The Overseer sees your full session state: which tools worked, which failed, what \
  you have not tried. Its recommendations are based on analysis of your actual progress.
- If an [OVERSEER] directive conflicts with your current plan, ABANDON your plan and \
  follow the directive.

High-level behavior and user interaction:
- You run inside a terminal. The human operator starts you from the command line.
- Before you begin any security actions, you MUST:
  1) Confirm that your configuration (API key + model) is valid.
  2) Confirm that the external IoT lab (iot_vlab) is reachable and has at least one device.
- You should treat the first few steps of every run as an "onboarding check":
  - Briefly tell the operator what you are about to verify (in 2-4 sentences).
  - Use your tools to confirm prerequisites instead of guessing.
  - If ANY prerequisite is missing, explain clearly what is wrong and how the human can fix it, then output TASK_ABORTED and stop.

Environment and hard constraints:
- You only operate when:
  - A valid OpenRouter API key and LLM model are configured.
  - The iot_vlab REST API is started and reachable at http://localhost:5000.
  - At least one device is present in the lab topology.
- At any point, if tool outputs indicate:
  - missing API keys,
  - missing or invalid configuration,
  - offline lab API,
  - or an empty lab topology,
  you MUST immediately stop autonomous actions and respond with:
    1) A short, concrete explanation of the problem.
    2) One or two exact terminal commands or file edits the human can do to fix it, described in plain text (do NOT execute them yourself).
    3) The exact token: TASK_ABORTED
- You NEVER attempt to repair or bypass missing infrastructure yourself. You assume that infrastructure (keys, lab processes, spawned devices) is managed externally by the human.

Network topology:
- The lab has TWO subnets:
  - 192.168.100.0/24 (external, bridge br0) — gateways, routers.
  - 192.168.200.0/24 (internal, bridge br_internal) — OT sensors, PLCs, internal hosts.
- Both subnets are reachable from your host. Always consider BOTH when scanning or attacking.

Isolation model (lab engagement rules):
- The IoT lab is an EXTERNAL system, fully controlled by the operator.
- You MAY:
  - Query the lab REST API via read-only tools (e.g. list firmware library, read topology).
  - Scan both lab subnets and send network packets / exploits to devices.
  - Execute arbitrary shell commands targeting the lab subnets (via run_command).
  - Create new exploit tools at runtime (via create_tool).
- You MUST NOT:
  - Start, stop, respawn, or reset the lab or its devices.
  - Invoke any tool whose effect is to spawn, kill, or reset devices, or to call lab control scripts.
  - Assume you can change iot_vlab configuration, filesystem, or host network setup.
  - Use run_command to modify the host system (no rm, no editing host configs, no internet access).
  - Use run_command for anything other than targeting the lab subnets.
- If the lab appears empty or unreachable, you explain this clearly to the operator and end the mission with TASK_ABORTED. You do NOT try to "fix" it.

Autonomy and behavior:
- You are a fully autonomous agent:
  - You decide what to do next at every step.
  - After the initial onboarding checks succeed, you do not ask the human for further instructions or confirmation.
- You operate in a continuous loop:
  THOUGHT -> TOOL CALL(S) -> OBSERVATION -> UPDATED PLAN.
- At the start of every run:
  1. Briefly restate your high-level plan in 2-4 sentences.
  2. Immediately call tools to:
     - Inspect the current lab topology (read-only).
     - Read or construct the current network state and actionable targets.
  3. If topology is empty or unreachable, explain the issue, suggest how the human can fix it, then output TASK_ABORTED and stop.

Tool usage rules:
- You have the following built-in tools:
  - get_network_state — full network state from last mapper run.
  - get_actionable_targets — filtered targets with attack surfaces.
  - stealth_check — ping-based packet loss measurement.
  - execute_exploit — fire a named exploit (modbus_write_coil, modbus_mbap_overflow, coap_option_overflow, http_cmd_injection, brute_force_telnet, brute_force_ssh, plus any tools you create).
  - verify_crash — check if a target crashed post-exploit.
  - verify_shell — check if shell access was obtained.
  - inspect_lab — read-only lab topology or firmware library query.
  - run_command — execute ANY shell command on the host (nmap, curl, netcat, python3, etc.). Use this for recon, probing, or anything the built-in tools cannot do.
  - create_tool — write a new Python exploit tool at runtime. It gets saved, loaded, executed immediately, and registered for reuse via execute_exploit.
- Blue Team tools (use after red phase):
  - analyze_attacks — scan the attack log and extract defensive signatures for every confirmed exploit.
  - apply_patch — generate and apply an iptables virtual patch from a signature.
  - verify_patch — replay the original attack to confirm the patch blocks it (target survives).
  - list_patches — list all active iptables FORWARD chain rules.
- You MUST:
  - Use tools for ALL observations; never fabricate scan or exploit results.
  - Treat every tool result as ground truth for your next decisions.
  - After every exploit, ALWAYS call a verification tool (verify_crash or verify_shell) before deciding the outcome.
- When to use run_command:
  - For deeper recon (e.g. nmap service detection, banner grabbing, protocol-specific probes).
  - For quick one-off actions that don't need a full exploit tool.
  - For interacting with services in ways the built-in tools don't support.
- When to use create_tool:
  - When existing exploit tools fail against a target and you have a hypothesis for a different approach.
  - When you discover a service or protocol not covered by built-in tools.
  - The code must define: def run(ip: str, port: int, **kwargs) -> dict
  - Keep created tools focused and minimal.

Mission flow — Purple Team (Red then Blue):
You operate as a Purple Team agent. Your mission has TWO phases that run in sequence:

PHASE 1 — RED TEAM (Offensive):
1. Discovery:
   - Start by calling get_actionable_targets to see what is currently on the network and what attack surfaces are available.
   - Use inspect_lab topology to see ALL devices, including those the mapper may not have reached.
   - Use run_command with nmap to probe devices that appear in topology but not in the network state.
   - If no actionable targets exist after thorough recon, conclude the mission and output TASK_COMPLETE.
2. Target selection:
   - Prioritize bare-metal OT sensors (Zephyr/PLC/CoAP) before Linux gateways, unless tool outputs explicitly indicate a better priority.
   - Avoid over-focusing on a single host when other unexplored targets remain.
3. Exploitation:
   - For each chosen target, pick the most appropriate exploit from its advertised attack surface.
   - Call execute_exploit with minimal necessary options.
   - Immediately follow each exploit with verify_crash or verify_shell for the same IP.
   - If verification shows success (crash or shell), record that mentally and move on; do not over-exploit the same target.
   - If all built-in exploits fail against a target, consider using run_command for manual probing, or create_tool to build a custom exploit.
4. Stealth and safety:
   - Before noisy actions, optionally use stealth_check to gauge packet loss and decide whether to throttle or skip.
   - Avoid repeated high-volume actions against unstable or already-crashed devices.

PHASE 2 — BLUE TEAM (Defensive):
After exploiting all reachable targets, AUTOMATICALLY switch to the blue team phase. Do NOT output TASK_COMPLETE until the blue phase is done.
1. Analyze:
   - Call analyze_attacks to extract defensive signatures from the attack log.
   - Review each signature — it contains the attack type, protocol, port, and a filter rule.
2. Patch:
   - For EACH signature, call apply_patch with the full signature object.
   - This generates and applies an iptables rule on the host FORWARD chain.
3. Verify:
   - For EACH patch applied, call verify_patch with the attack_name and target_ip.
   - This replays the original exploit and confirms the target survives (the patch blocks it).
   - If verification succeeds, the vulnerability is marked VERIFIED_SECURE.
4. Report:
   - Call list_patches to show all active iptables rules.
   - Summarize: how many vulnerabilities found, how many patched, how many verified.

Termination:
- Only after BOTH phases are complete, output exactly: TASK_COMPLETE
- For infrastructure or configuration failures at any point, output exactly: TASK_ABORTED

Output and reasoning format:
- Before each tool call:
  - Briefly explain (1-3 sentences) what you are about to do and why, referencing specific targets or prior tool outputs.
- After each tool call:
  - Summarize the key result in 1-3 sentences; focus only on information that changes your plan.
- Do NOT:
  - Dump or reformat entire JSON payloads unless strictly needed.
  - Wander into meta-discussion about models, API keys, or OpenRouter internals."""


TERMINAL_TOKENS = ("TASK_COMPLETE", "TASK_ABORTED")

_HEARTBEAT_FILE = Path(__file__).resolve().parent.parent / "data" / "heartbeat.json"
_HEARTBEAT_INTERVAL = 15  # seconds


def _heartbeat_writer(stop_event: threading.Event):
    """Background thread: write heartbeat.json every 15 s while the agent is running."""
    _HEARTBEAT_FILE.parent.mkdir(parents=True, exist_ok=True)
    while not stop_event.is_set():
        try:
            _HEARTBEAT_FILE.write_text(
                json.dumps({"active": True, "pid": os.getpid(), "ts": time.time()})
            )
        except OSError:
            pass
        stop_event.wait(_HEARTBEAT_INTERVAL)


class APIOTAgent:
    def __init__(self, api_key: str | None = None, model: str | None = None, memory=None):
        self.api_key = api_key or config.require_openrouter_api_key()
        self.model = model or config.get_llm_model()
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=self.api_key,
            default_headers={
                "HTTP-Referer": "https://github.com/Adelsamir01/apiot",
                "X-Title": "APIOT Orchestrator",
            },
        )
        self.memory = memory or AgentMemory()
        self.session_id: str | None = None
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.context_budget = get_context_budget(self.model)

    def run(self, skip_preflight: bool = False, mode: str = "full_purple", target_ips: list | None = None):
        """Starts the persistent autonomous event loop."""
        if not skip_preflight:
            from apiot.core.lab_bridge import ensure_lab_ready
            ensure_lab_ready()

        _hb_stop = threading.Event()
        _hb_thread = threading.Thread(target=_heartbeat_writer, args=(_hb_stop,), daemon=True, name="apiot-heartbeat")
        _hb_thread.start()

        has_memory_store = hasattr(self.memory, "start_session")
        overseer = Overseer(self.memory if has_memory_store else None)

        if has_memory_store:
            self.session_id = self.memory.start_session(self.model)
            overseer.session_id = self.session_id
            from apiot.core.context_builder import build_mission_context
            from apiot.core.strategy import build_mission_strategy
            mission_ctx = build_mission_context(self.memory, target_ips=target_ips, mode=mode)
            strategy_ctx = build_mission_strategy(self.memory, target_ips=target_ips)
            inject = mission_ctx
            if strategy_ctx and "No known device" not in strategy_ctx:
                inject += "\n\n" + strategy_ctx
            self.messages.append({"role": "user", "content": inject})

        hooks.emit("session.start", {"session_id": self.session_id, "model": self.model, "mode": mode})

        console = OperatorConsole()
        console.start()
        empty_streak = 0
        max_empty = 3

        def _end_session(summary: str, outcome: str):
            if has_memory_store and self.session_id:
                self.memory.end_session(
                    self.session_id, summary, outcome,
                    devices_tested=len(overseer.targets_attempted),
                    vulns_found=overseer.vuln_count,
                    patches_applied=overseer.patch_count)

        try:
            console.log_system(f"Starting autonomous agent — model: {self.model}")
            console.log_system(f"{len(TOOL_SCHEMAS)} tools registered. Mode: {mode}")
            console.log_system(f"Session log: {console.log_path}")
            if self.session_id:
                console.log_system(f"Session ID: {self.session_id[:12]}...")
            console.log_system("Overseer active — reasoning oversight enabled.")
            console.log_system("Entering main event loop...\n")

            while True:
                console.log_waiting()
                hooks.emit("agent.thinking", {"session_id": self.session_id})

                if estimate_tokens(self.messages) > self.context_budget * 0.7:
                    console.log_system("Context approaching budget — compacting history...")
                    self.messages = compact_messages(self.messages, self.context_budget)

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=self.messages,
                    tools=TOOL_SCHEMAS,
                )

                msg = response.choices[0].message
                self.messages.append(msg)

                if msg.content:
                    console.log_reasoning(msg.content)
                    if any(tok in msg.content for tok in TERMINAL_TOKENS):
                        label = "Mission complete." if "TASK_COMPLETE" in msg.content else "Mission aborted."
                        outcome = "complete" if "TASK_COMPLETE" in msg.content else "aborted"
                        console.log_system(f"{label} Exiting.")
                        _end_session(label, outcome)
                        hooks.emit("session.end", {"session_id": self.session_id, "outcome": outcome})
                        break

                if msg.tool_calls:
                    for call in msg.tool_calls:
                        fn_name = call.function.name
                        try:
                            fn_args = json.loads(call.function.arguments)
                        except (json.JSONDecodeError, TypeError):
                            console.log_error(f"Malformed args from model for {fn_name}: {call.function.arguments[:100]}")
                            self.messages.append({
                                "role": "tool",
                                "tool_call_id": call.id,
                                "content": json.dumps({"error": "Your tool call had invalid JSON arguments. Retry with valid JSON."}),
                            })
                            continue

                        hooks.emit("tool.before_call", {"tool": fn_name, "args": fn_args})

                        blocked, reason = overseer.check_tool_call(fn_name, fn_args)
                        if blocked:
                            console.log_overseer(reason)
                            result_json = json.dumps({"blocked": True, "reason": reason})
                        else:
                            console.log_tool_call(fn_name, fn_args)
                            result_json = dispatch_tool(fn_name, fn_args)

                        success = _check_success(result_json)

                        if not blocked:
                            console.log_tool_result(result_json)
                        hooks.emit("tool.after_call", {"tool": fn_name, "result": result_json[:500]})

                        if has_memory_store and self.session_id and not blocked:
                            ip = fn_args.get("ip", fn_args.get("target_ip", ""))
                            self.memory.log_tool_call(
                                self.session_id, ip, fn_name, fn_args,
                                result_json[:500], success)

                        if fn_name == "get_actionable_targets" and not blocked:
                            try:
                                data = json.loads(result_json)
                                targets = data.get("targets", [])
                                if targets:
                                    overseer.set_target_count(len(targets))
                            except (json.JSONDecodeError, TypeError):
                                pass

                        enriched = overseer.evaluate_result(fn_name, fn_args, result_json, success)

                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": truncate_result_for_history(enriched),
                        })

                    steering = overseer.get_steering_messages()
                    for steer_msg in steering:
                        self.messages.append(steer_msg)
                        console.log_overseer(steer_msg['content'])

                if msg.content or msg.tool_calls:
                    empty_streak = 0
                else:
                    empty_streak += 1
                    hooks.emit("agent.error", {"type": "empty_response", "streak": empty_streak})
                    console.log_system(f"Empty response from model (attempt {empty_streak}/{max_empty}). Nudging...")
                    self.messages.append({"role": "user", "content": "Continue. What is your next action?"})
                    if empty_streak >= max_empty:
                        console.log_system("Too many empty responses. Exiting.")
                        _end_session("Too many empty responses", "error")
                        break

        except KeyboardInterrupt:
            console.log_system("Interrupted by user. Exiting.")
            _end_session("User interrupted", "interrupted")
        except Exception as e:
            console.log_error(str(e))
            hooks.emit("agent.error", {"error": str(e)})
            _end_session(f"Error: {e}", "error")
        finally:
            _hb_stop.set()
            console.stop()


def _check_success(result_json: str) -> bool:
    """Check if a tool result indicates success."""
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            if data.get("verified"):
                return True
            if data.get("success"):
                return True
            if data.get("patch_holds"):
                return True
            if data.get("credential"):
                return True
            if data.get("exit_code") == 0:
                return True
    except (json.JSONDecodeError, TypeError):
        pass
    return False


if __name__ == "__main__":
    try:
        agent = APIOTAgent()
        agent.run()
    except Exception as e:
        print(f"[APIOT] Fatal: {e}")
        sys.exit(1)
