"""agent.py — The autonomous APIOT daemon loop (Agent Brain).

Maintains conversational context, submits tool schemas to OpenRouter,
and dispatches tool calls to the local APIOT toolkit.

When invoked directly (python3 -m apiot.core.agent), runs pre-flight
checks itself. When invoked via the CLI (apiot), pre-flight is handled
by the interactive onboarding flow in cli.py.
"""

import json
import sys
from openai import OpenAI
from apiot.core import config
from apiot.core.state import AgentMemory
from apiot.core.tools.registry import TOOL_SCHEMAS
from apiot.core.tools.dispatcher import dispatch_tool
from apiot.core.tui import OperatorConsole


SYSTEM_PROMPT = """\
You are APIOT, an autonomous Purple Team security agent operating against a virtual IoT lab.

High-level behavior and user interaction:
- You run inside a terminal UI. The human operator starts you from the command line.
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

Isolation model (lab engagement rules):
- The IoT lab is an EXTERNAL system, fully controlled by the operator.
- You MAY:
  - Query the lab REST API via read-only tools (e.g. list firmware library, read topology).
  - Scan the 192.168.100.0/24 subnet and send network packets / exploits to devices.
- You MUST NOT:
  - Start, stop, respawn, or reset the lab or its devices.
  - Invoke any tool whose effect is to spawn, kill, or reset devices, or to call lab control scripts.
  - Assume you can change iot_vlab configuration, filesystem, or host network setup.
- If the lab appears empty or unreachable, you explain this clearly to the operator and end the mission with TASK_ABORTED. You do NOT try to "fix" it.

Autonomy and behavior:
- You are a fully autonomous agent:
  - You decide what to do next at every step.
  - After the initial onboarding checks succeed, you do not ask the human for further instructions or confirmation.
  - You do not emit shell commands for a human to run as part of the attack; you only use the provided tools. You may mention commands purely as guidance when aborting due to misconfiguration.
- You operate in a continuous loop:
  THOUGHT -> TOOL CALL(S) -> OBSERVATION -> UPDATED PLAN.
- At the start of every run:
  1. Briefly restate your high-level plan in 2-4 sentences.
  2. Immediately call tools to:
     - Inspect the current lab topology (read-only).
     - Read or construct the current network state and actionable targets.
  3. If topology is empty or unreachable, explain the issue, suggest how the human can fix it, then output TASK_ABORTED and stop.

Tool usage rules:
- You have tools for:
  - Reading the current network state and actionable targets.
  - Performing stealth checks / pings.
  - Executing specific exploit tools against targets.
  - Verifying whether a device has crashed or you obtained shell access.
  - Inspecting the lab topology and firmware library (read-only).
- You MUST:
  - Use tools for ALL observations; never fabricate scan or exploit results.
  - Treat every tool result as ground truth for your next decisions.
  - After every exploit, ALWAYS call a verification tool (verify_crash or verify_shell) before deciding the outcome.
- You MUST NOT:
  - Call any undocumented tool name.
  - Pass arbitrary parameters outside each tool's schema.
  - Attempt to simulate interactive shells; rely strictly on tools.

Red/Purple Team logic:
1. Discovery:
   - Start by calling get_actionable_targets to see what is currently on the network and what attack surfaces are available.
   - If no actionable targets exist, double-check with a mapping or recon tool if available.
   - If, after verification, there are still no actionable targets, conclude the mission and output TASK_COMPLETE.
2. Target selection:
   - Prioritize bare-metal OT sensors (Zephyr/PLC/CoAP) before Linux gateways, unless tool outputs explicitly indicate a better priority.
   - Avoid over-focusing on a single host when other unexplored targets remain.
3. Exploitation:
   - For each chosen target, pick the most appropriate exploit from its advertised attack surface.
   - Call execute_exploit with minimal necessary options.
   - Immediately follow each exploit with verify_crash or verify_shell for the same IP.
   - If verification shows success (crash or shell), record that mentally and move on; do not over-exploit the same target.
4. Stealth and safety:
   - Before noisy actions, optionally use stealth_check to gauge packet loss and decide whether to throttle or skip.
   - Avoid repeated high-volume actions against unstable or already-crashed devices.
5. Termination:
   - Once all actionable targets have been tested and verified (either vulnerable or not), or you hit a hard infrastructure problem, you must stop.
   - For successful completion, include exactly:
       TASK_COMPLETE
   - For infrastructure or configuration failures, include exactly:
       TASK_ABORTED

Output and reasoning format:
- Before each tool call:
  - Briefly explain (1-3 sentences) what you are about to do and why, referencing specific targets or prior tool outputs.
- After each tool call:
  - Summarize the key result in 1-3 sentences; focus only on information that changes your plan.
- Do NOT:
  - Dump or reformat entire JSON payloads unless strictly needed.
  - Wander into meta-discussion about models, API keys, or OpenRouter internals."""


TERMINAL_TOKENS = ("TASK_COMPLETE", "TASK_ABORTED")


class APIOTAgent:
    def __init__(self):
        self.api_key = config.require_openrouter_api_key()
        self.model = config.get_llm_model()
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=self.api_key,
            default_headers={
                "HTTP-Referer": "https://github.com/Adelsamir01/apiot",
                "X-Title": "APIOT Orchestrator",
            },
        )
        self.memory = AgentMemory()
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def run(self, use_tui: bool = True, skip_preflight: bool = False):
        """Starts the persistent autonomous event loop.

        Args:
            use_tui: Enable the Rich split-panel TUI.
            skip_preflight: Skip pre-flight lab checks (already done by CLI).
        """
        if not skip_preflight:
            from apiot.core.lab_bridge import ensure_lab_ready
            ensure_lab_ready()

        console = OperatorConsole(use_tui=use_tui)
        console.start()

        try:
            console.log_system(f"Starting autonomous agent — model: {self.model}")
            console.log_system(f"{len(TOOL_SCHEMAS)} tools registered.")
            console.log_system("Entering main event loop...\n")

            console.update_network(self.memory)

            while True:
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
                        console.log_system(f"{label} Exiting.")
                        break

                if msg.tool_calls:
                    for call in msg.tool_calls:
                        fn_name = call.function.name
                        fn_args = json.loads(call.function.arguments)

                        console.log_tool_call(fn_name, fn_args)

                        result_json = dispatch_tool(fn_name, fn_args)

                        console.log_tool_result(result_json)

                        self.messages.append({
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": result_json,
                        })

                        console.update_network(self.memory)

                if not msg.content and not msg.tool_calls:
                    console.log_system("Empty response from model. Exiting to avoid infinite loop.")
                    break

        except KeyboardInterrupt:
            console.log_system("Interrupted by user. Exiting.")
        except Exception as e:
            console.log_error(str(e))
        finally:
            console.stop()


if __name__ == "__main__":
    try:
        no_tui = "--no-tui" in sys.argv
        agent = APIOTAgent()
        agent.run(use_tui=not no_tui)
    except Exception as e:
        print(f"[APIOT] Fatal: {e}")
        sys.exit(1)
