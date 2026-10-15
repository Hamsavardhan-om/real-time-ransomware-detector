#!/usr/bin/env python3
"""
RansomShield User-Space Event Collector & Orchestrator.

Spawns the native eBPF sensor_loader, reads raw kernel events, applies
normalization (schema validation + Shannon entropy enrichment), logs to JSONL,
and optionally renders the live Rich Terminal Dashboard.
"""

import os
import sys
import json
import time
import signal
import argparse
import subprocess
from pathlib import Path

# Add project root to python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collector.normalizer import EventNormalizer
from collector.dashboard import TelemetryDashboard
from rich.live import Live
from rich.console import Console

def main():
    parser = argparse.ArgumentParser(description="RansomShield eBPF Collector")
    parser.add_argument("--watch-dir", default="/tmp/ransomware_sandbox",
                        help="Monitored directory subtree (default: /tmp/ransomware_sandbox)")
    parser.add_argument("--output", default="datasets/events.jsonl",
                        help="JSONL output dataset file path (default: datasets/events.jsonl)")
    parser.add_argument("--dashboard", action="store_true", default=True,
                        help="Enable live Rich Terminal Dashboard (default: True)")
    parser.add_argument("--no-dashboard", dest="dashboard", action="store_false",
                        help="Disable dashboard, print raw JSON lines to stdout")
    parser.add_argument("--target-pid", type=int, default=0,
                        help="Optional PID filter (0 = all processes)")
    parser.add_argument("--no-entropy", action="store_true",
                        help="Disable file Shannon entropy calculation")
    args = parser.parse_args()

    # Ensure output directory exists
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Ensure watch directory exists
    if args.watch_dir:
        Path(args.watch_dir).mkdir(parents=True, exist_ok=True)

    # Path to sensor_loader
    project_root = Path(__file__).parent.parent
    loader_bin = project_root / "ebpf" / "sensor_loader"
    bpf_obj = project_root / "ebpf" / "sensor.bpf.o"

    if not loader_bin.exists() or not bpf_obj.exists():
        console = Console()
        console.print("[bold red]Error: eBPF binaries not found. Please run 'make' first.[/]")
        sys.exit(1)

    cmd = [
        str(loader_bin),
        "--bpf", str(bpf_obj),
        "--collector-pid", str(os.getpid()),
    ]
    if args.watch_dir:
        cmd.extend(["--watch-dir", args.watch_dir])
    if args.target_pid > 0:
        cmd.extend(["--target-pid", str(args.target_pid)])

    normalizer = EventNormalizer(compute_entropy=not args.no_entropy)
    dashboard = TelemetryDashboard(watch_dir=args.watch_dir) if args.dashboard else None

    # Open output file
    out_file = open(out_path, "a", encoding="utf-8")

    # Start sensor subprocess
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    def cleanup(signum=None, frame=None):
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        out_file.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    console = Console()
    console.print(f"[bold green][+] RansomShield Collector running on PID {os.getpid()}[/]")
    console.print(f"[+] Output trace file: [cyan]{out_path}[/]")
    console.print(f"[+] Sandbox watch dir: [cyan]{args.watch_dir}[/]")

    if args.dashboard:
        with Live(dashboard.render(), refresh_per_second=4, screen=False) as live:
            for line in proc.stdout:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    raw_data = json.loads(line)
                    normalized = normalizer.normalize(raw_data)
                    # Write to dataset file
                    out_file.write(json.dumps(normalized) + "\n")
                    out_file.flush()

                    # Update UI
                    dashboard.push_event(normalized)
                    live.update(dashboard.render())
                except json.JSONDecodeError:
                    continue
    else:
        for line in proc.stdout:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                raw_data = json.loads(line)
                normalized = normalizer.normalize(raw_data)
                out_file.write(json.dumps(normalized) + "\n")
                out_file.flush()
                print(json.dumps(normalized))
            except json.JSONDecodeError:
                continue

    cleanup()

if __name__ == "__main__":
    main()
