import time
from collections import deque, defaultdict
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class TelemetryDashboard:
    """
    Unified Dual-Tier Terminal Dashboard (TUI) for RansomShield.
    Integrates:
    - Tier 1: AI Threat Triage & Explainable Evidence (Option B Live Model & MLRan)
    - Tier 2: Real-Time Kernel Telemetry, Burst Velocity Meters, & Decision Engine Containment
    """
    def __init__(self, watch_dir: str = "", max_history: int = 10, sample_id: Optional[str] = None):
        self.watch_dir = watch_dir
        self.max_history = max_history
        self.sample_id = sample_id
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

        # Process threat and containment tracking
        self.process_threats: Dict[int, Dict[str, Any]] = {}

        # Recent events for display
        self.recent_events: deque[Dict[str, Any]] = deque(maxlen=max_history)
        self.latest_mitigation: Optional[Dict[str, Any]] = None

        # Tier 1 AI Triage State
        self.latest_ai_triage: Optional[Dict[str, Any]] = None
        self.baseline_triage: Optional[Dict[str, Any]] = None
        self.current_entropy: float = 0.0

    def set_baseline_triage(self, baseline: Dict[str, Any]):
        """Sets pre-execution MLRan baseline report (e.g. from --sample-id)."""
        self.baseline_triage = baseline

    def push_ai_triage(self, triage: Dict[str, Any]):
        """Updates live Tier 1 AI inference and explainability evidence."""
        now = time.time()
        triage["ts"] = now
        if not self.latest_ai_triage:
            self.latest_ai_triage = triage
            return

        curr_prob = self.latest_ai_triage.get("probability", 0.0)
        new_prob = triage.get("probability", 0.0)
        curr_age = now - self.latest_ai_triage.get("ts", now)

        # Prioritize higher severity threats:
        # If new triage is a higher threat (or equal), update immediately.
        # If new triage is lower threat, only downgrade after 6.0 seconds of no high threat.
        if new_prob >= curr_prob or curr_age > 6.0:
            self.latest_ai_triage = triage

    def push_mitigation_alert(self, mitigation: Dict[str, Any]):
        """Records active mitigation from the Decision Engine with timestamp."""
        mitigation["ts"] = time.time()
        self.latest_mitigation = mitigation
        pid = mitigation.get("pid", 0)
        if pid:
            action = mitigation.get("action_taken", "")
            status = "FROZEN (SIGSTOP)" if "ISOLATE" in action else ("TERMINATED (SIGKILL)" if "KILL" in action else "MITIGATED")
            if pid in self.process_threats:
                self.process_threats[pid]["status"] = status
            else:
                self.process_threats[pid] = {
                    "score": mitigation.get("threat_score", 90.0),
                    "level": mitigation.get("threat_level", "CRITICAL"),
                    "status": status,
                }

    def update_process_threat(self, pid: int, score: float, level: str, status: str = "RUNNING"):
        """Updates per-process threat assessment for process tree."""
        curr = self.process_threats.get(pid, {})
        # Do not overwrite frozen or terminated status
        old_status = curr.get("status", "RUNNING")
        if old_status in ("FROZEN (SIGSTOP)", "TERMINATED (SIGKILL)"):
            status = old_status

        self.process_threats[pid] = {
            "score": score,
            "level": level,
            "status": status,
        }

    def push_event(self, event: Dict[str, Any]):
        """Ingests a new normalized event and updates metrics."""
        now = time.time()
        self.total_events += 1
        ev_type = event.get("event_type", "OTHER")
        pid = event.get("pid", 0)
        proc = event.get("process", "unknown")
        exe = event.get("exe", proc)
        bytes_count = event.get("bytes", 0)
        entropy = float(event.get("extra", {}).get("entropy", 0.0))
        if entropy > 0.0:
            self.current_entropy = entropy

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

    def _purge_old_timestamps(self, window_sec: float = 2.0):
        cutoff = time.time() - window_sec
        while self.event_timestamps and self.event_timestamps[0] < cutoff:
            self.event_timestamps.popleft()
        while self.write_timestamps and self.write_timestamps[0] < cutoff:
            self.write_timestamps.popleft()
        while self.rename_timestamps and self.rename_timestamps[0] < cutoff:
            self.rename_timestamps.popleft()

    def render(self) -> Layout:
        """Constructs the unified Rich Layout view bringing Tier 1 and Tier 2 together."""
        self._purge_old_timestamps(window_sec=2.0)
        now = time.time()
        uptime = now - self.start_time

        # Fast 2.0-second rate calculation for immediate burst detection and rapid recovery
        write_rate = len(self.write_timestamps) / 2.0
        rename_rate = len(self.rename_timestamps) / 2.0
        overall_rate = len(self.event_timestamps) / 2.0

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="alert_banner", size=3),
            Layout(name="upper_dashboard", size=11),
            Layout(name="body", ratio=1),
        )
        layout["upper_dashboard"].split_row(
            Layout(name="tier1_ai", ratio=1),
            Layout(name="tier2_telemetry", ratio=1),
        )
        layout["body"].split_row(
            Layout(name="events", ratio=2),
            Layout(name="processes", ratio=1),
        )

        # 1. Header
        header_text = Text()
        header_text.append(" 🛡️  RANSOMSHIELD DUAL-TIER PLATFORM: TIER 1 AI TRIAGE + TIER 2 KERNEL eBPF DEFENSE ", style="bold white on blue")
        header_text.append(f"  Uptime: {uptime:.1f}s | Watch: {self.watch_dir or 'ALL'} | Events: {self.total_events}", style="dim")
        layout["header"].update(Panel(header_text, style="blue"))

        # 2. Alert / Mitigation Banner (With 6-second TTL so it does not stay forever)
        mitigation_active = self.latest_mitigation and (now - self.latest_mitigation.get("ts", 0) < 6.0)
        if mitigation_active:
            m = self.latest_mitigation
            q_cnt = len(m.get("quarantined_files", []))
            banner_text = Text()
            banner_text.append(f" 🚨 DECISION ENGINE: Process '{m.get('process')}' (PID {m.get('pid')}) {m.get('action_taken')}! ", style="bold white on red")
            banner_text.append(f" Threat: {m.get('threat_score', 0):.0f} [{m.get('threat_level')}] | Quarantined: {q_cnt} files | {m.get('message')}", style="bold yellow")
            layout["alert_banner"].update(Panel(banner_text, style="red"))
        else:
            status_text = Text(" ✓ DECISION ENGINE ACTIVE: Policy=Auto-Isolate (SIGSTOP) & Quarantine | Live ML Model (Option B) Active", style="green dim")
            layout["alert_banner"].update(Panel(status_text, style="green"))

        # 3. TIER 1: AI Threat Triage & Explainable Evidence Panel
        t1_content = self._render_tier1_panel()
        layout["upper_dashboard"]["tier1_ai"].update(
            Panel(t1_content, title="[bold cyan]TIER 1: AI Threat Triage & Explainability (Option B / MLRan)[/]", border_style="cyan")
        )

        # 4. TIER 2: Live Kernel Telemetry & Burst Meters Panel
        t2_content = self._render_tier2_panel(overall_rate, write_rate, rename_rate)
        layout["upper_dashboard"]["tier2_telemetry"].update(
            Panel(t2_content, title="[bold green]TIER 2: In-Kernel Syscall Telemetry & Detection Heuristics[/]", border_style="green")
        )

        # 5. Live Normalized Event Feed
        ev_table = Table(expand=True, box=None, header_style="bold magenta")
        ev_table.add_column("Time", width=9)
        ev_table.add_column("PID", width=7)
        ev_table.add_column("Process", width=11)
        ev_table.add_column("Event Type", width=13)
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
                ent = ev.get("extra", {}).get("entropy")
                ent_str = f" [H={ent}]" if ent else ""
                detail = f"{detail} ({ev.get('bytes', 0)}B){ent_str}"

            ev_table.add_row(
                t_str,
                str(ev.get("pid")),
                ev.get("process", ""),
                f"[{color}]{etype}[/]",
                detail,
            )

        layout["body"]["events"].update(Panel(ev_table, title="[bold]📜 Live Normalized Event Feed (eBPF Stream)[/]", border_style="cyan"))

        # 6. Active Process Tree & AI Risk Matrix
        proc_table = Table(expand=True, box=None, header_style="bold yellow")
        proc_table.add_column("PID", width=6)
        proc_table.add_column("Process", width=10)
        proc_table.add_column("Writes", width=6)
        proc_table.add_column("Renames", width=7)
        proc_table.add_column("AI Risk", width=9)
        proc_table.add_column("Status", width=15)

        sorted_procs = sorted(
            self.process_stats.items(),
            key=lambda x: (x[1]["writes"] + x[1]["renames"] + x[1]["deletes"]),
            reverse=True
        )[:8]

        for pid, s in sorted_procs:
            pt = self.process_threats.get(pid, {"score": 0.0, "level": "LOW", "status": "RUNNING"})
            sc = pt.get("score", 0.0)
            st = pt.get("status", "RUNNING")

            if sc >= 81.0:
                risk_style = "bold red"
            elif sc >= 51.0:
                risk_style = "bold yellow"
            else:
                risk_style = "green"

            if "FROZEN" in st:
                status_style = "bold red reverse"
            elif "TERMINATED" in st:
                status_style = "bold white on red"
            else:
                status_style = "green"

            proc_table.add_row(
                str(pid),
                s["name"][:10],
                str(s["writes"]),
                str(s["renames"]),
                f"[{risk_style}]{sc:.0f}%[/]",
                f"[{status_style}]{st}[/]",
            )

        layout["body"]["processes"].update(Panel(proc_table, title="[bold]🌳 Active Process Tree & AI Threat Matrix[/]", border_style="yellow"))

        return layout

    def _render_tier1_panel(self) -> Table:
        """Renders the Tier 1 AI Triage & Explainability breakdown."""
        t1 = self.latest_ai_triage or self.baseline_triage

        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)

        if not t1:
            grid.add_row(Text(" [i] Awaiting active process file operations in watch directory...", style="dim italic"))
            grid.add_row(Text(" [•] Status: STANDBY (Monitoring for zero-day encryption bursts)", style="green"))
            grid.add_row(Text(" [•] Model: Option B Live Event-Window Classifier (Grounded in MLRan dataset)", style="dim"))
            grid.add_row(Text(" [•] Baseline: 4,880 JNCA 2026 binaries, 64 Ransomware Families", style="dim"))
            return grid

        verdict = t1.get("verdict", "UNKNOWN")
        prob = t1.get("probability", 0.0)
        conf = t1.get("confidence", 0.0)
        ptype = t1.get("predicted_type", "UNKNOWN")
        pfam = t1.get("predicted_family", "Unknown")
        top_feats = t1.get("top_features", [])

        if verdict == "RANSOMWARE":
            v_badge = "[bold white on red] 🚨 CLASSIFICATION: RANSOMWARE [/]"
            prob_text = f"[bold red]{prob * 100:.1f}% Threat Probability[/] | [bold yellow]{conf * 100:.1f}% Confidence[/]"
        else:
            v_badge = "[bold white on green] ✓ CLASSIFICATION: GOODWARE [/]"
            prob_text = f"[bold green]{(1.0 - prob) * 100:.1f}% Benign Confidence[/] | [dim]{prob * 100:.1f}% Risk[/]"

        grid.add_row(f"{v_badge}  {prob_text}")
        grid.add_row(f" [bold]Operational Profile:[/] Type: [bold cyan]{ptype}[/] | Family: [bold yellow]{pfam}[/]")

        # Explainability evidence
        if top_feats:
            grid.add_row("[bold underline]Key Deciding Behavioral Evidence (Explainable AI):[/]")
            for i, feat in enumerate(top_feats[:3], 1):
                label = feat.get("label", feat.get("feature", ""))
                val_str = feat.get("value_str", "")
                impact = feat.get("impact", 0.0)
                is_pos = feat.get("is_positive", impact > 0)
                tag = "[bold red][RANSOMWARE][/]" if is_pos else "[bold green][GOODWARE][/]"
                weight_str = f"+{impact:.2f}" if impact >= 0 else f"{impact:.2f}"
                grid.add_row(f"  {i}. {tag} {label} ({val_str}) -> Weight: {weight_str}")
        else:
            grid.add_row("[dim]  Active behavioral traits within normal operational thresholds.[/]")

        return grid

    def _render_tier2_panel(self, overall_rate: float, write_rate: float, rename_rate: float) -> Table:
        """Renders Tier 2 In-Kernel Telemetry & Heuristic Threat Gauges."""
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        w_style = "bold red" if write_rate >= 25.0 else ("yellow" if write_rate >= 10.0 else "green")
        r_style = "bold red" if rename_rate >= 8.0 else ("yellow" if rename_rate >= 3.0 else "green")
        e_style = "bold red" if self.current_entropy >= 7.0 else ("yellow" if self.current_entropy >= 5.5 else "green")

        if write_rate >= 25.0 or rename_rate >= 8.0 or self.current_entropy >= 7.0:
            status_text = "[bold red blink]CRITICAL / BURST DETECTED[/]"
        elif write_rate >= 10.0 or rename_rate >= 3.0:
            status_text = "[bold yellow]ELEVATED FILE ACTIVITY[/]"
        else:
            status_text = "[bold green]NORMAL BASELINE[/]"

        grid.add_row(
            f" [bold]Event Throughput:[/] [bold cyan]{overall_rate:.1f}[/] ops/sec",
            f" [bold]Write Burst Rate:[/] [{w_style}]{write_rate:.1f}[/] writes/sec (Limit: 25/s)",
        )
        grid.add_row(
            f" [bold]Rename Burst Rate:[/] [{r_style}]{rename_rate:.1f}[/] renames/sec (Limit: 8/s)",
            f" [bold]Shannon Entropy:[/] [{e_style}]{self.current_entropy:.2f}[/] / 8.0 (Crypto: >7.0)",
        )
        grid.add_row(
            f" [bold]Heuristic Alarm:[/] {status_text}",
            " [bold]Kernel Probes:[/] [dim]CO-RE tracepoints attached[/]",
        )
        grid.add_row(
            " [bold]Response Policy:[/] [yellow]Auto-Freeze (SIGSTOP) + Vault Quarantine[/]",
            " [bold]Audit Engine:[/] [dim]SQLite batched sync active[/]",
        )
        return grid
