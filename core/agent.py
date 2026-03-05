"""agent.py — The autonomous APIOT daemon loop (Agent Brain).

Maintains conversational context, submits tool schemas to OpenRouter,
and dispatches tool calls to the local APIOT toolkit.
"""

import json
import sys
from openai import OpenAI
from apiot.core import config
from apiot.core.state import AgentMemory
from apiot.core.tools.registry import TOOL_SCHEMAS
from apiot.core.tools.dispatcher import dispatch_tool
from apiot.core.lab_bridge import ensure_lab_ready
from apiot.core.tui import OperatorConsole


SYSTEM_PROMPT = (
    "You are APIOT, an autonomous Purple Team security agent orchestrating an emulated IoT network.\n"
    "Your lab subnet is 192.168.100.0/24.\n\n"
    "You have access to tools that let you interact with the network and the lab environment.\n"
    "USE YOUR TOOLS. Do not simulate or imagine results. Call the tools and read their output.\n\n"
    "Rules of Engagement (Red Team Runbook):\n"
    "1. Start by calling get_actionable_targets to discover what is on the network.\n"
    "2. For each target, pick an appropriate exploit from the attack surface and call execute_exploit.\n"
    "3. ALWAYS call verify_crash or verify_shell immediately after every attack. Never assume success.\n"
    "4. If a target crashes, move to the next one. Do not retry crashed targets indefinitely.\n"
    "5. Once all targets have been assessed and verified, output the text TASK_COMPLETE.\n\n"
    "Important:\n"
    "- Do not generate shell commands or code. Use ONLY the provided tools.\n"
    "- Reason briefly about your plan before each tool call.\n"
    "- Output TASK_COMPLETE (exactly) when your mission is done."
)


class APIOTAgent:
    def __init__(self):
        self.api_key = config.get_openrouter_api_key()
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

    def run(self, skip_bootstrap: bool = False, use_tui: bool = True):
        """Starts the persistent autonomous event loop."""
        # --- Stage 3: Pre-flight lab bootstrap ---
        # Run bootstrap BEFORE starting the TUI so its prints don't mess up rendering
        ensure_lab_ready(skip_bootstrap=skip_bootstrap)

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

                # --- Handle text output ---
                if msg.content:
                    console.log_reasoning(msg.content)
                    if "TASK_COMPLETE" in msg.content:
                        console.log_system("Mission complete. Exiting.")
                        break

                # --- Handle tool calls ---
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

                # --- Guard: no content and no tool calls means the model is stuck ---
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
        skip = "--skip-bootstrap" in sys.argv
        no_tui = "--no-tui" in sys.argv
        agent = APIOTAgent()
        agent.run(skip_bootstrap=skip, use_tui=not no_tui)
    except Exception as e:
        print(f"Failed to initialize Agent: {e}")
        sys.exit(1)
