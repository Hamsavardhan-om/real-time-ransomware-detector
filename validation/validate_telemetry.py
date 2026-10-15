#!/usr/bin/env python3
"""
Telemetry Validation & Benchmark Engine.

Runs controlled synthetic workloads with known ground truth event counts and compares
them against the captured eBPF telemetry to verify accuracy, integrity, and drop rates.
Generates an academic evaluation report for reviews and viva.
"""

import os
import sys
import json
import time
import shutil
import signal
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

def run_workload_subprocess(sandbox_dir: str, num_ops: int = 25) -> dict:
    """Executes a known number of operations in a separate process and returns ground truth."""
    code = f"""
import os, json, socket, time
from pathlib import Path

sandbox = Path("{sandbox_dir}")
sandbox.mkdir(parents=True, exist_ok=True)
my_pid = os.getpid()

gt = {{
    "pid": my_pid,
    "FILE_WRITE": 0,
    "FILE_READ": 0,
    "FILE_RENAME": 0,
    "FILE_DELETE": 0,
    "NET_CONNECT": 0,
    "bytes_written": 0,
}}

test_content = b"TELEMETRY_VALIDATION_PACKET_2026_" * 4 # 136 bytes
files = []
for i in range({num_ops}):
    p = sandbox / f"val_file_{{i}}.dat"
    with open(p, "wb") as f:
        f.write(test_content)
    gt["FILE_WRITE"] += 1
    gt["bytes_written"] += len(test_content)
    files.append(p)

for p in files:
    with open(p, "rb") as f:
        _ = f.read()
    gt["FILE_READ"] += 1

renamed_files = []
for p in files:
    new_p = p.with_suffix(".renamed")
    os.rename(p, new_p)
    gt["FILE_RENAME"] += 1
    renamed_files.append(new_p)

for new_p in renamed_files:
    os.unlink(new_p)
    gt["FILE_DELETE"] += 1

for port in [80, 443]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect_ex(("1.1.1.1", port))
        s.close()
        gt["NET_CONNECT"] += 1
    except Exception:
        pass

print(json.dumps(gt))
"""
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    for line in res.stdout.splitlines():
        if line.startswith("{") and "pid" in line:
            return json.loads(line)
    raise RuntimeError("Failed to parse ground truth from workload output")

def validate_telemetry(trace_file: str, ground_truth: dict, sandbox_dir: str):
    """Parses captured JSONL trace and compares against ground truth."""
    captured = {
        "FILE_WRITE": 0,
        "FILE_READ": 0,
        "FILE_RENAME": 0,
        "FILE_DELETE": 0,
        "NET_CONNECT": 0,
        "bytes_written": 0,
    }

    events = []
    with open(trace_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # Determine the workload PID from the file events in sandbox
    workload_pid = ground_truth.get("pid")
    for ev in events:
        path = ev.get("path") or ""
        if "val_file_" in path:
            workload_pid = ev.get("pid")
            break

    total_events_in_trace = len(events)
    for ev in events:
        ev_pid = ev.get("pid")
        etype = ev.get("event_type")
        path = ev.get("path") or ""
        old_path = ev.get("extra", {}).get("old_path", "")

        # Match workload PID or direct sandbox paths
        is_workload = (ev_pid == workload_pid) or (sandbox_dir in path) or (sandbox_dir in old_path)
        if is_workload:
            if etype in captured:
                captured[etype] += 1
            if etype == "FILE_WRITE":
                captured["bytes_written"] += ev.get("bytes", 0)

    return captured, total_events_in_trace, workload_pid

def main():
    console = Console()
    sandbox = "/tmp/telemetry_validation_sandbox"
    trace_path = "/tmp/validation_trace.jsonl"

    if os.path.exists(sandbox):
        shutil.rmtree(sandbox)
    if os.path.exists(trace_path):
        os.remove(trace_path)

    project_root = Path(__file__).parent.parent
    loader_bin = project_root / "ebpf" / "sensor_loader"
    bpf_obj = project_root / "ebpf" / "sensor.bpf.o"

    console.print(Panel("[bold cyan]RansomShield Telemetry Sensor - Benchmark & Ground Truth Validation[/]", border_style="cyan"))

    # Start sensor
    cmd = [
        str(loader_bin),
        "--bpf", str(bpf_obj),
        "--watch-dir", sandbox,
        "--jsonl", trace_path,
        "--collector-pid", str(os.getpid()),
        "--no-stdout"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1) # Allow BPF probes to attach

    # Execute known workload in isolated process
    num_ops = 30
    console.print(f"[*] Executing controlled workload with {num_ops} operations per category in target process...")
    gt = run_workload_subprocess(sandbox, num_ops=num_ops)
    console.print(f"    Target Process PID: [bold cyan]{gt['pid']}[/]")

    time.sleep(1) # Allow ring buffer to flush
    proc.send_signal(signal.SIGINT)
    proc.wait(timeout=3)

    # Analyze results
    captured, total_events, workload_pid = validate_telemetry(trace_path, gt, sandbox)

    table = Table(title="Telemetry Accuracy Scorecard", header_style="bold blue")
    table.add_column("Event Category", style="bold")
    table.add_column("Ground Truth", justify="right")
    table.add_column("Captured by eBPF", justify="right")
    table.add_column("Capture Rate (%)", justify="right")
    table.add_column("Status", justify="center")

    total_gt = 0
    total_cap = 0

    categories = [
        ("FILE_WRITE (File Writes)", "FILE_WRITE"),
        ("FILE_READ (File Reads)", "FILE_READ"),
        ("FILE_RENAME (File Renames)", "FILE_RENAME"),
        ("FILE_DELETE (File Unlinks)", "FILE_DELETE"),
        ("NET_CONNECT (Network Outbound)", "NET_CONNECT"),
    ]

    for label, cat in categories:
        exp = gt[cat]
        act = captured[cat]
        total_gt += exp
        total_cap += act
        rate = (act / exp * 100.0) if exp > 0 else 100.0
        status = "[bold green]PASS[/]" if rate >= 95.0 else "[bold red]FAIL[/]"
        table.add_row(label, str(exp), str(act), f"{rate:.1f}%", status)

    overall_rate = (total_cap / total_gt * 100.0) if total_gt > 0 else 100.0
    table.add_section()
    table.add_row(
        "[bold]TOTAL EVENTS[/]",
        f"[bold]{total_gt}[/]",
        f"[bold]{total_cap}[/]",
        f"[bold green]{overall_rate:.1f}%[/]",
        "[bold green]VERIFIED (>=95%)[/]" if overall_rate >= 95.0 else "[bold red]FAIL[/]"
    )

    console.print(table)
    console.print(f"[bold green][+] Total Telemetry Stream Integrity: {overall_rate:.1f}% accuracy[/]")
    console.print(f"    - Target Process PID: {gt['pid']}")
    console.print(f"    - Total Events in Trace: {total_events}")
    console.print(f"    - Bytes Written Ground Truth: {gt['bytes_written']} bytes")
    console.print(f"    - Bytes Written Captured: {captured['bytes_written']} bytes")
    console.print(f"    - Validation Dataset Saved to: [cyan]{trace_path}[/]")

if __name__ == "__main__":
    main()
