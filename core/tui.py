"""tui.py — Rich Terminal User Interface for APIOT.

Provides a vertically split layout:
- Left: Scrolling agent execution log (thoughts, tool calls, results).
- Right: Live network topology and status table.
"""

import json
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

class OperatorConsole:
    def __init__(self, use_tui=True):
        self.use_tui = use_tui
        self.console = Console()
        self.log_messages = []
        self.max_log_lines = 100
        
        # Network state snapshot
        self.network_state = {}
        
        if self.use_tui:
            self.layout = self.make_layout()
            self.live = Live(self.layout, refresh_per_second=4, console=self.console)
        else:
            self.live = None

    def start(self):
        if self.live:
            self.live.start()

    def stop(self):
        if self.live:
            self.live.stop()

    def make_layout(self) -> Layout:
        layout = Layout(name="root")
        layout.split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1)
        )
        return layout

    def _update_display(self):
        if not self.use_tui:
            return

        # Render left panel
        log_text = Text("\n\n").join(self.log_messages[-self.max_log_lines:])
        self.layout["left"].update(Panel(log_text, title="[bold blue]Agent Flow", border_style="blue"))

        # Render right panel
        table = Table(title="Live Network Map", expand=True)
        table.add_column("IP Address", style="cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Status", justify="center")

        hosts = self.network_state.get("fingerprints", {})
        vulns = self.network_state.get("active_vulnerabilities", {})
        
        # Determine host status based on vulnerabilities
        crashed_ips = set()
        shell_ips = set()
        for v in vulns.values():
            if v.get("attack") == "crash_verified":
                crashed_ips.add(v.get("ip"))
            elif v.get("attack") == "shell_access":
                shell_ips.add(v.get("ip"))

        for ip, fp in hosts.items():
            cls = fp.get("classification", {})
            cat = cls.get("category", "Unknown")
            
            status = "[green]ONLINE[/green]"
            if ip in crashed_ips:
                status = "[red]CRASHED[/red]"
            elif ip in shell_ips:
                status = "[yellow]COMPROMISED[/yellow]"

            table.add_row(ip, cat, status)

        stats_text = Text(f"\nDiscovered Hosts: {len(hosts)} | Active Vulns: {len(vulns)}")
        right_group = Group(table, stats_text)
        
        self.layout["right"].update(Panel(right_group, title="[bold green]Network & Stats", border_style="green"))

    def _add_log(self, text: Text):
        self.log_messages.append(text)
        if len(self.log_messages) > self.max_log_lines:
            self.log_messages.pop(0)
        
        if not self.use_tui:
            self.console.print(text)
        else:
            self._update_display()

    def log_system(self, message: str):
        self._add_log(Text(f"[APIOT] {message}", style="bold white"))

    def log_reasoning(self, content: str):
        self._add_log(Text(f"\n[🧠 Agent Reasoning]\n{content}", style="italic bright_white"))

    def log_tool_call(self, name: str, args: dict):
        args_str = json.dumps(args, indent=2)
        self._add_log(Text(f"⚡ [Tool Call] {name}\nArgs: {args_str}", style="bold yellow"))

    def log_tool_result(self, result: str):
        display = result[:500] + "..." if len(result) > 500 else result
        self._add_log(Text(f"↳ [Tool Result] {display}\n", style="dim green"))

    def log_error(self, message: str):
        self._add_log(Text(f"❌ [Error] {message}", style="bold red"))

    def update_network(self, memory):
        try:
            self.network_state = memory.get_full_context()
        except Exception:
            self.network_state = {}
        self._update_display()
