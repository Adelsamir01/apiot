"""cli.py — Interactive Mission Control CLI for APIOT."""

import os, sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def _save_env(key: str, value: str):
    """Persist a key=value pair to the .env file."""
    lines = []
    replaced = False
    if _ENV_PATH.exists():
        for line in _ENV_PATH.read_text().splitlines():
            if line.startswith(f"{key}="):
                lines.append(f'{key}="{value}"')
                replaced = True
            else:
                lines.append(line)
    if not replaced:
        lines.append(f'{key}="{value}"')
    _ENV_PATH.write_text("\n".join(lines) + "\n")

MISSIONS = {
    "1": ("full_purple", "Full Purple Team — Red + Blue on all devices"),
    "2": ("targeted_red", "Targeted Red — Pick specific IPs to attack"),
    "3": ("novel", "Novel Exploitation — Creative attacks on known devices"),
    "4": ("blue_only", "Blue Only — Patch and verify existing findings"),
    "5": ("recon", "Reconnaissance Only — Scan and enumerate, no exploits"),
}


def _display_network_history(memory):
    """Show session history and known devices from memory."""
    sessions = memory.get_session_history(limit=5)
    if sessions:
        t = Table(title="Recent Sessions", show_lines=False, expand=False)
        t.add_column("ID", style="dim", max_width=10)
        t.add_column("Outcome")
        t.add_column("Vulns")
        t.add_column("Patches")
        for s in sessions:
            t.add_row(s["id"][:8], s.get("outcome", "?"),
                       str(s.get("vulns_found", 0)), str(s.get("patches_applied", 0)))
        console.print(t)
    else:
        console.print("[dim]No prior sessions found.[/dim]")

    profiles = memory.get_all_device_profiles()
    if profiles:
        t = Table(title="Known Devices", show_lines=False, expand=False)
        t.add_column("IP", style="cyan")
        t.add_column("Name")
        t.add_column("Status")
        t.add_column("Creds")
        for p in profiles:
            t.add_row(p["ip"], p.get("device_name", "?"),
                       p.get("status", "unknown"), p.get("known_creds", "-"))
        console.print(t)

    findings = memory.get_open_findings()
    if findings:
        console.print(f"\n[yellow]Open vulnerabilities: {len(findings)}[/yellow]")
        for f in findings[:8]:
            console.print(f"  • {f['ip']}: {f['finding_type']} via {f['tool_used']}")

    patches = memory.get_active_patches()
    if patches:
        verified = sum(1 for p in patches if p.get("verified"))
        console.print(f"[green]Active patches: {len(patches)} ({verified} verified)[/green]")


def _select_mission(memory):
    """Interactive mission mode selection."""
    console.print(Panel("[bold]Mission Control[/bold]", style="blue"))
    _display_network_history(memory)

    console.print("\n[bold]Select Mission Mode:[/bold]")
    for k, (_, desc) in MISSIONS.items():
        console.print(f"  [cyan]{k}[/cyan] — {desc}")

    choice = Prompt.ask("\nMission", choices=list(MISSIONS.keys()), default="1")
    mode, desc = MISSIONS[choice]

    target_ips = None
    if mode == "targeted_red":
        profiles = memory.get_all_device_profiles()
        if profiles:
            console.print("\n[bold]Available targets:[/bold]")
            for p in profiles:
                console.print(f"  [cyan]{p['ip']}[/cyan] — {p.get('device_name', '?')}")
        raw = Prompt.ask("Target IPs (comma-separated)")
        target_ips = [ip.strip() for ip in raw.split(",") if ip.strip()]

    console.print(f"\n[bold green]Mission:[/bold green] {desc}")
    if target_ips:
        console.print(f"[bold green]Targets:[/bold green] {', '.join(target_ips)}")

    if not Confirm.ask("Launch?", default=True):
        console.print("[dim]Aborted.[/dim]")
        sys.exit(0)

    return mode, target_ips


def run():
    """Entry point for the APIOT CLI."""
    console.print(Panel("[bold cyan]APIOT — Autonomous IoT Security Agent[/bold cyan]"))

    from apiot.core.config import get_openrouter_api_key, get_llm_model

    api_key = get_openrouter_api_key()
    if not api_key:
        api_key = Prompt.ask("[yellow]OpenRouter API key[/yellow]")
    os.environ["OPENROUTER_API_KEY"] = api_key
    _save_env("OPENROUTER_API_KEY", api_key)
    console.print("[green]✓ API key saved[/green]")

    model = os.environ.get("LLM_MODEL", "").strip()
    if not model:
        model = get_llm_model()
    use_default = Confirm.ask(f"Use model [cyan]{model}[/cyan]?", default=True)
    if not use_default:
        model = Prompt.ask("[yellow]Model[/yellow]", default="openai/gpt-4o")
    os.environ["LLM_MODEL"] = model
    _save_env("LLM_MODEL", model)
    console.print(f"[green]✓ Model: {model}[/green]")

    vlab_url = os.environ.get("VLAB_API", "http://localhost:5000")
    try:
        import urllib.request, json as _json
        resp = urllib.request.urlopen(f"{vlab_url}/api/ready", timeout=10)
        data = _json.loads(resp.read())
        if data.get("ready"):
            console.print(f"[green]✓ iot_vlab ready at {vlab_url} ({data.get('total', '?')} devices)[/green]")
        else:
            console.print(f"[yellow]⚠ iot_vlab reachable but {data.get('pending', '?')} device(s) still booting[/yellow]")
            if not Confirm.ask("Wait and continue?", default=True):
                sys.exit(1)
    except Exception:
        console.print(f"[red]⚠ Cannot reach iot_vlab at {vlab_url}[/red]")
        if not Confirm.ask("Continue anyway?", default=False):
            sys.exit(1)

    from apiot.core.memory_store import MemoryStore
    from apiot.core.agent import APIOTAgent

    memory = MemoryStore()

    while True:
        mode, target_ips = _select_mission(memory)
        agent = APIOTAgent(api_key=api_key, model=model, memory=memory)
        agent.run(mode=mode, target_ips=target_ips)

        console.print("\n[bold cyan]Mission ended.[/bold cyan]")
        if not Confirm.ask("Start another mission?", default=True):
            break
        console.print("[dim]Loading updated network state and findings...[/dim]\n")


def main():
    run()


if __name__ == "__main__":
    sys.exit(main())

