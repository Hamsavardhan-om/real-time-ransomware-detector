import time
from collections import deque, defaultdict
from typing import Dict, Any, List
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

class TelemetryDashboard:
    """
    Polished Real-Time Terminal Dashboard (TUI) for RansomShield eBPF Sensor.
    Provides live throughput meters, active process tracking, and event stream visualization.
    """
    def __init__(self, watch_dir: str = "", max_history: int = 12):
        self.watch_dir = watch_dir
        self.max_history = max_history
        self.start_time = time.time()
        self.total_events = 0

        # Rolling event window for rate calculation (last 5 seconds)
        self.event_timestamps = deque()
        self.write_timestamps = deque()
        self.rename_timestamps = deque()

        # Cumulative metrics
        self.event_counts = defaultdict(int)
        self.process_stats = defaultdict(lambda: {
            "name": "", "exe": "", "writes": 0, "reads": 0, "renames": 0, "deletes": 0, "bytes": 0
        })

        # Recent events for display
        self.recent_events: deque[Dict[str, Any]] = deque(maxlen=max_history)

    def push_event(self, event: Dict[str, Any]):
        """Ingests a new normalized event and updates metrics."""
        now = time.time()
        self.total_events += 1
        ev_type = event.get("event_type", "OTHER")
        pid = event.get("pid", 0)
        proc = event.get("process", "unknown")
        exe = event.get("exe", proc)
        bytes_count = event.get("bytes", 0)

        self.event_timestamps.append(now)
        self.event_counts[ev_type] += 1

        if ev_type == "FILE_WRITE":
            self.write_timestamps.append(now)
        elif ev_type == "FILE_RENAME":
            self.rename_timestamps.append(now)

        # Process stats
        pstat = self.process_stats[pid]
        pstat["name"] = proc
        pstat["exe"] = exe
        if ev_type == "FILE_WRITE":
            pstat["writes"] += 1
            pstat["bytes"] += bytes_count
        elif ev_type == "FILE_READ":
            pstat["reads"] += 1
        elif ev_type == "FILE_RENAME":
            pstat["renames"] += 1
        elif ev_type == "FILE_DELETE":
            pstat["deletes"] += 1

        self.recent_events.append(event)

    def _purge_old_timestamps(self, window_sec: float = 5.0):
        cutoff = time.time() - window_sec
        while self.event_timestamps and self.event_timestamps[0] < cutoff:
            self.event_timestamps.popleft()
        while self.write_timestamps and self.write_timestamps[0] < cutoff:
            self.write_timestamps.popleft()
        while self.rename_timestamps and self.rename_timestamps[0] < cutoff:
            self.rename_timestamps.popleft()

    def render(self) -> Layout:
        """Constructs the Rich Layout view."""
        self._purge_old_timestamps()
        uptime = time.time() - self.start_time

        write_rate = len(self.write_timestamps) / 5.0
        rename_rate = len(self.rename_timestamps) / 5.0
        overall_rate = len(self.event_timestamps) / 5.0

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="metrics", size=6),
            Layout(name="body", ratio=1),
        )
        layout["body"].split_row(
            Layout(name="events", ratio=2),
            Layout(name="processes", ratio=1),
        )

        # 1. Header
        header_text = Text()
        header_text.append(" 🛡️  RANSOMSHIELD eBPF SENSOR & TELEMETRY PIPELINE ", style="bold white on blue")
        header_text.append(f"  Uptime: {uptime:.1f}s | Watch Dir: {self.watch_dir or 'ALL'} | Total Events: {self.total_events}", style="dim")
        layout["header"].update(Panel(header_text, style="blue"))

        # 2. Metrics Panel
        metrics_table = Table.grid(expand=True)
        metrics_table.add_column(ratio=1)
        metrics_table.add_column(ratio=1)
        metrics_table.add_column(ratio=1)
        metrics_table.add_column(ratio=1)

        w_style = "bold red" if write_rate >= 30.0 else ("yellow" if write_rate >= 10.0 else "green")
        r_style = "bold red" if rename_rate >= 10.0 else ("yellow" if rename_rate >= 3.0 else "green")
        threat_text = "[bold green]NORMAL[/]"
        if write_rate >= 30.0 or rename_rate >= 10.0:
            threat_text = "[bold red blink]CRITICAL / BURST DETECTED[/]"
        elif write_rate >= 10.0 or rename_rate >= 3.0:
            threat_text = "[bold yellow]ELEVATED ACTIVITY[/]"

        metrics_table.add_row(
            Panel(f"[bold cyan]{overall_rate:.1f}[/] ops/sec\n[dim]Kernel Throughput[/]", title="Event Rate"),
            Panel(f"[{w_style}]{write_rate:.1f}[/] writes/sec\n[dim]R1 Threshold: 30.0/s[/]", title="Write Burst Rate"),
            Panel(f"[{r_style}]{rename_rate:.1f}[/] renames/sec\n[dim]R2 Threshold: 10.0/s[/]", title="Rename Burst Rate"),
            Panel(f"{threat_text}\n[dim]Live Heuristic Alarm[/]", title="Sensor Threat Level"),
        )
        layout["metrics"].update(metrics_table)

        # 3. Live Event Stream
        ev_table = Table(expand=True, box=None, header_style="bold magenta")
        ev_table.add_column("Time", width=10)
        ev_table.add_column("PID", width=7)
        ev_table.add_column("Process", width=12)
        ev_table.add_column("Event Type", width=14)
        ev_table.add_column("Target Path / Detail", ratio=1)

        type_colors = {
            "FILE_WRITE": "bold yellow",
            "FILE_READ": "cyan",
            "FILE_RENAME": "bold magenta",
            "FILE_DELETE": "bold red",
            "FILE_OPEN": "blue",
            "FILE_CLOSE": "dim",
            "NET_CONNECT": "bold green",
            "PROCESS_EXEC": "white",
            "PROCESS_EXIT": "dim red",
        }

        for ev in reversed(self.recent_events):
            t_str = f"{ev['timestamp']:.2f}"[-8:]
            etype = ev.get("event_type", "OTHER")
            color = type_colors.get(etype, "white")
            detail = ev.get("path") or ""
            if etype == "NET_CONNECT":
                detail = f"dst={ev.get('dst_ip')}:{ev.get('dst_port')} ({ev.get('protocol')})"
            elif etype == "FILE_RENAME":
                old = ev.get("extra", {}).get("old_path", "")
                detail = f"{old} -> {ev.get('path')}"
            elif etype == "FILE_WRITE":
                entropy = ev.get("extra", {}).get("entropy")
                ent_str = f" [H={entropy}]" if entropy else ""
                detail = f"{detail} ({ev.get('bytes', 0)}B){ent_str}"

            ev_table.add_row(
                t_str,
                str(ev.get("pid")),
                ev.get("process", ""),
                f"[{color}]{etype}[/]",
                detail,
            )

        layout["events"].update(Panel(ev_table, title="[bold]Live Normalized Event Feed[/]", border_style="cyan"))

        # 4. Active Process Tracking
        proc_table = Table(expand=True, box=None, header_style="bold cyan")
        proc_table.add_column("PID", width=6)
        proc_table.add_column("Process", width=10)
        proc_table.add_column("Writes", width=6)
        proc_table.add_column("Renames", width=7)
        proc_table.add_column("Deletes", width=7)

        # Top processes by activity
        sorted_procs = sorted(self.process_stats.items(), key=lambda x: (x[1]["writes"] + x[1]["renames"] + x[1]["deletes"]), reverse=True)[:8]
        for pid, s in sorted_procs:
            proc_table.add_row(
                str(pid),
                s["name"][:10],
                str(s["writes"]),
                str(s["renames"]),
                str(s["deletes"]),
            )

        layout["processes"].update(Panel(proc_table, title="[bold]Active Process Tree[/]", border_style="green"))

        return layout
