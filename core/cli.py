"""cli.py — Interactive terminal entry point for APIOT.

Provides a guided onboarding flow:
  1. Banner and welcome.
  2. API key check (prompt to enter if missing).
  3. Lab connectivity check (wait or abort).
  4. Device topology check.
  5. Network mapping.
  6. Mode selection menu.
  7. Launch into the chosen mode.
"""

import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

from apiot.core import config

console = Console()

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

BANNER = r"""
    ___    ____  ________  ______
   /   |  / __ \/  _/ __ \/_  __/
  / /| | / /_/ // // / / / / /
 / ___ |/ ____// // /_/ / / /
/_/  |_/_/   /___/\____/ /_/

  Autonomous Purple IoT Toolkit
"""


def _print_banner():
    console.print(Panel(
        Text(BANNER, style="bold cyan", justify="center"),
        border_style="bright_blue",
        subtitle="[dim]v2.1.0[/dim]",
    ))


def _step(number: int, label: str):
    console.print(f"\n[bold white]  [{number}/5] {label}[/bold white]")


def _ok(msg: str):
    console.print(f"        [bold green]OK[/bold green]  {msg}")


def _fail(msg: str):
    console.print(f"        [bold red]FAIL[/bold red]  {msg}")


def _warn(msg: str):
    console.print(f"        [bold yellow]WARN[/bold yellow]  {msg}")


def _info(msg: str):
    console.print(f"        [dim]{msg}[/dim]")


# ── Step 1: API key ──────────────────────────────────────────────────

def _check_api_key() -> str:
    """Check for API key in env/.env. Prompt interactively if missing."""
    _step(1, "OpenRouter API Key")

    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if key:
        masked = key[:12] + "..." + key[-4:]
        _ok(f"Key loaded: {masked}")
        return key

    _warn("OPENROUTER_API_KEY not found in environment or .env file.")
    _info("The autonomous agent requires an OpenRouter API key to function.")
    _info(f"You can get one at https://openrouter.ai/keys\n")

    key = Prompt.ask("        Enter your OpenRouter API key").strip()
    if not key:
        _fail("No key provided. Cannot continue.")
        raise SystemExit(1)

    _save_env_key("OPENROUTER_API_KEY", key)
    os.environ["OPENROUTER_API_KEY"] = key
    masked = key[:12] + "..." + key[-4:]
    _ok(f"Key saved to .env: {masked}")
    return key


def _check_model() -> str:
    """Check for LLM model config. Use default if not set."""
    model = os.getenv("LLM_MODEL", "").strip()
    if model:
        _info(f"Model: {model}")
        return model

    default = "anthropic/claude-3.5-sonnet"
    _info(f"LLM_MODEL not set, using default: {default}")
    _save_env_key("LLM_MODEL", default)
    os.environ["LLM_MODEL"] = default
    return default


def _save_env_key(key: str, value: str):
    """Append or update a key in the .env file."""
    lines = []
    found = False
    if _ENV_PATH.exists():
        for line in _ENV_PATH.read_text().splitlines():
            if line.startswith(f"{key}="):
                lines.append(f'{key}="{value}"')
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f'{key}="{value}"')
    _ENV_PATH.write_text("\n".join(lines) + "\n")


# ── Step 2: Lab connectivity ─────────────────────────────────────────

def _check_lab_online() -> bool:
    """Check if iot_vlab REST API is reachable."""
    _step(2, "Lab Connectivity")

    import requests
    url = "http://localhost:5000/topology"
    max_retries = 5
    interval = 2

    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                _ok("iot_vlab REST API is reachable at http://localhost:5000")
                return True
        except (requests.ConnectionError, requests.Timeout):
            pass

        if attempt < max_retries:
            _info(f"Waiting for lab API... ({attempt + 1}/{max_retries})")
            time.sleep(interval)

    _fail("iot_vlab REST API is not reachable at http://localhost:5000")
    _info("Start the lab manually in another terminal:")
    _info("  cd ../iot_vlab && sudo python3 lab_api.py")
    _info("Then re-run: apiot")
    return False


# ── Step 3: Device topology ──────────────────────────────────────────

def _check_topology() -> list[dict]:
    """Check that the lab has devices."""
    _step(3, "Device Topology")

    from apiot.toolkit.lab_client import LabClient
    lab = LabClient()
    topo = lab.get_topology()

    if not topo:
        _fail("Lab has no devices.")
        _info("Spawn targets via the iot_vlab API or interactive wizard:")
        _info("  curl -X POST http://localhost:5000/spawn -H 'Content-Type: application/json' -d '{\"firmware_id\": \"zephyr_coap\"}'")
        _info("  curl -X POST http://localhost:5000/spawn -H 'Content-Type: application/json' -d '{\"firmware_id\": \"dvrf_v03\"}'")
        _info("Then re-run: apiot")
        return []

    table = Table(show_header=True, header_style="bold magenta", padding=(0, 2))
    table.add_column("Firmware", style="cyan")
    table.add_column("IP", style="white")
    table.add_column("Alive", justify="center")

    for d in topo:
        alive = "[green]YES[/green]" if d.get("alive") else "[red]NO[/red]"
        table.add_row(d.get("firmware_id", "?"), d.get("ip", "?"), alive)

    _ok(f"{len(topo)} device(s) found:")
    console.print(table)
    return topo


# ── Step 4: Network mapper ───────────────────────────────────────────

def _run_mapper():
    """Run the network mapper."""
    _step(4, "Network Mapping")
    _info("Scanning 192.168.100.0/24 subnet...")

    try:
        from apiot.core.mapper import NetworkMapper
        mapper = NetworkMapper()
        ctx = mapper.run()
        n = len(ctx.get("fingerprints", {}))
        _ok(f"Mapped {n} target(s). network_state.json updated.")
    except Exception as e:
        _warn(f"Mapper failed (non-fatal): {e}")
        _info("The agent can still discover targets using its tools.")


# ── Step 5: Mode selection ───────────────────────────────────────────

def _select_mode() -> str:
    """Present the mode selection menu."""
    _step(5, "Mission Mode")

    console.print()
    console.print("        [bold]1[/bold]  [cyan]Autonomous Red Team[/cyan]")
    console.print("           Fully autonomous attack + verification loop.")
    console.print("           The LLM decides everything — you just watch.\n")
    console.print("        [bold]2[/bold]  [cyan]Manual CLI Harness[/cyan]")
    console.print("           You drive tool commands one at a time via the CLI.")
    console.print("           Run: [dim]sudo python3 -m apiot.core.agent_loop get_targets[/dim]\n")
    console.print()

    choice = Prompt.ask(
        "        Select mode",
        choices=["1", "2"],
        default="1",
    )
    return "autonomous" if choice == "1" else "manual"


# ── Main ─────────────────────────────────────────────────────────────

def main():
    _print_banner()

    # Step 1: API key
    try:
        api_key = _check_api_key()
        model = _check_model()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")
        return 1

    # Step 2: Lab connectivity
    if not _check_lab_online():
        return 1

    # Step 3: Topology
    topo = _check_topology()
    if not topo:
        return 1

    # Step 4: Network mapping
    _run_mapper()

    # Step 5: Mode selection
    try:
        mode = _select_mode()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")
        return 1

    if mode == "manual":
        console.print("\n[bold green]Ready.[/bold green] Use the CLI harness:")
        console.print("  [dim]sudo python3 -m apiot.core.agent_loop get_targets[/dim]")
        console.print("  [dim]sudo python3 -m apiot.core.agent_loop attack <tool> <ip>[/dim]")
        console.print("  [dim]sudo python3 -m apiot.core.agent_loop verify_crash <ip>[/dim]")
        console.print()
        return 0

    # Autonomous mode: launch the agent
    console.print("\n[bold green]Launching autonomous agent...[/bold green]\n")

    from apiot.core.agent import APIOTAgent
    try:
        agent = APIOTAgent()
        agent.run(use_tui=True, skip_preflight=True)
    except KeyboardInterrupt:
        console.print("\n[dim]Agent interrupted.[/dim]")
    except Exception as e:
        console.print(f"\n[bold red]Agent error:[/bold red] {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
