"""cli.py — Interactive entry point for the APIOT terminal application.

This is the main user-facing CLI. It displays a banner, prompts the user
for configuration (subnet, API key, lab bootstrap), and then hands off
to the autonomous agent loop.
"""

import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.align import Align

console = Console()

BANNER = r"""
    _    ____ ___ ___ _____ 
   / \  |  _ \_ _/ _ \_   _|
  / _ \ | |_) | | | | || |  
 / ___ \|  __/| | |_| || |  
/_/   \_\_|  |___\___/ |_|  

  Agentic Purple IoT Toolkit
"""


def _save_env(key: str, value: str, env_path: Path):
    """Upsert a key=value pair in the given .env file."""
    lines = []
    if env_path.exists():
        lines = env_path.read_text().splitlines()

    updated = False
    for i, line in enumerate(lines):
        if line.startswith(f"{key}=") or line.startswith(f"{key} ="):
            lines[i] = f'{key}="{value}"'
            updated = True
            break

    if not updated:
        lines.append(f'{key}="{value}"')

    env_path.write_text("\n".join(lines) + "\n")


def _get_api_key(env_path: Path) -> str:
    """Return existing key or prompt the user for one."""
    from apiot.core import config
    try:
        return config.get_openrouter_api_key()
    except ValueError:
        pass

    console.print("\n[yellow]No OpenRouter API key found.[/yellow]")
    key = Prompt.ask("  Enter your OpenRouter API key", password=True)
    if key.strip():
        _save_env("OPENROUTER_API_KEY", key.strip(), env_path)
        # Reload
        from dotenv import load_dotenv
        load_dotenv(env_path, override=True)
    return key.strip()


def main():
    """Interactive entry point — presents prompts and launches the agent."""
    console.clear()
    console.print(Panel(Align.center(Text(BANNER, style="bold green")), border_style="green"))

    env_path = Path(__file__).resolve().parent.parent / ".env"

    # --- Step 1: API Key ---
    api_key = _get_api_key(env_path)
    if not api_key:
        console.print("[bold red]No API key provided. Exiting.[/bold red]")
        sys.exit(1)

    # --- Step 2: Target Subnet ---
    console.print()
    subnet = Prompt.ask(
        "  [bold cyan]Target subnet[/bold cyan]",
        default="192.168.100.0/24",
    )

    # --- Step 3: Lab Bootstrap ---
    console.print()
    skip_bootstrap = not Confirm.ask(
        "  [bold cyan]Auto-bootstrap the iot_vlab?[/bold cyan] (start API, spawn targets, run mapper)",
        default=True,
    )

    # --- Step 4: TUI preference ---
    console.print()
    no_tui = not Confirm.ask(
        "  [bold cyan]Enable split-panel TUI?[/bold cyan]",
        default=True,
    )

    console.print()
    console.print(f"  [green]✓[/green] Subnet: [bold]{subnet}[/bold]")
    console.print(f"  [green]✓[/green] Lab bootstrap: [bold]{'Yes' if not skip_bootstrap else 'No'}[/bold]")
    console.print(f"  [green]✓[/green] TUI: [bold]{'Yes' if not no_tui else 'No'}[/bold]")
    console.print()

    # --- Launch agent ---
    from apiot.core.agent import APIOTAgent
    try:
        agent = APIOTAgent(subnet=subnet)
        agent.run(skip_bootstrap=skip_bootstrap, use_tui=not no_tui)
    except Exception as e:
        console.print(f"[bold red]Failed to launch agent: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
