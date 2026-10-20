#!/usr/bin/env python3
"""
RansomShield User-Space Event Collector & Orchestrator.

Spawns the native eBPF sensor_loader, reads raw kernel events, applies
normalization (schema validation + Shannon entropy enrichment), logs to JSONL,
evaluates live Option B machine learning inference, and renders the unified
Dual-Tier Terminal Dashboard (Tier 1 AI Triage + Tier 2 Kernel Defense).
"""

import os
import sys
import json
import time
import signal
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

# Add project root to python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collections import defaultdict, deque
from dataclasses import asdict
from collector.normalizer import EventNormalizer
from collector.dashboard import TelemetryDashboard
from engine.storage import RansomShieldStorage
from engine.decision_engine import DecisionEngine
from models.live_classifier import LivePredictor
from rich.live import Live
from rich.console import Console

logger = logging.getLogger("ransomshield.collector")


def main():
    parser = argparse.ArgumentParser(description="RansomShield eBPF Collector & Unified Dual-Tier Dashboard")
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
    parser.add_argument("--action", choices=["isolate", "kill"], default="isolate",
                        help="Decision Engine policy: 'isolate' (SIGSTOP) or 'kill' (SIGKILL)")
    parser.add_argument("--no-mitigate", action="store_true",
                        help="Disable automated mitigation (observe and log only)")
    parser.add_argument("--sample-id", type=str, default="",
                        help="Optional MLRan sample ID to preload baseline Tier 1 triage")
    args = parser.parse_args()

    # Ensure output directory exists
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Ensure watch directory exists and is writable by all users
    if args.watch_dir:
        Path(args.watch_dir).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(args.watch_dir, 0o777)
        except Exception:
            pass

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
    dashboard = TelemetryDashboard(watch_dir=args.watch_dir, sample_id=args.sample_id) if args.dashboard else None

    # Preload MLRan baseline triage if sample ID specified
    if args.sample_id and dashboard:
        try:
            from models.mlran_predict import MLRanPredictor
            from models.mlran_loader import MLRanLoader
            loader = MLRanLoader()
            pred = MLRanPredictor()
            sample_report = pred.triage_sample_id(args.sample_id, loader=loader)
            dashboard.set_baseline_triage({
                "verdict": sample_report.get("verdict", "UNKNOWN"),
                "probability": sample_report.get("ransomware_probability", 0.0),
                "confidence": sample_report.get("confidence", 0.0),
                "predicted_type": sample_report.get("predicted_type", "UNKNOWN"),
                "predicted_family": sample_report.get("predicted_family", "Unknown"),
                "top_features": [
                    {
                        "label": f.get("feature_name", ""),
                        "value_str": "PRESENT",
                        "impact": f.get("weight", 0.0),
                        "is_positive": f.get("indicates") == "ransomware",
                    }
                    for f in sample_report.get("top_contributing_features", [])
                ],
            })
        except Exception as e:
            logger.debug(f"Could not preload MLRan sample {args.sample_id}: {e}")

    # Initialize Option B Live ML Predictor
    live_predictor = LivePredictor()

    # Open output file
    out_file = open(out_path, "a", encoding="utf-8")

    # Check root privileges on Linux
    if os.name != "nt" and os.geteuid() != 0:
        console = Console()
        console.print("[bold yellow][!] RansomShield eBPF Sensor requires root privileges to attach kernel tracepoints.[/]")
        console.print("[bold cyan][*] Automatically re-running with sudo...[/]\n")
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            console.print(f"[bold red]Failed to elevate with sudo: {e}. Please run: sudo python3 main.py monitor[/]")
            sys.exit(1)

    # Start sensor subprocess
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    time.sleep(0.1)
    if proc.poll() is not None:
        err = proc.stderr.read() if proc.stderr else "Unknown error"
        console = Console()
        console.print(f"[bold red]Error: eBPF sensor_loader exited immediately (code {proc.returncode}):[/]\n{err}")
        sys.exit(1)

    import threading
    import queue
    event_queue = queue.Queue()
    stop_reader = threading.Event()

    def reader_thread():
        while not stop_reader.is_set():
            if proc.stdout is None:
                break
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.01)
                continue
            line = line.strip()
            if line and line.startswith("{"):
                event_queue.put(line)

    t = threading.Thread(target=reader_thread, daemon=True)
    t.start()

    def cleanup(signum=None, frame=None):
        stop_reader.set()
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            storage.flush_events()
            out_file.close()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    console = Console()
    console.print(f"[bold green][+] RansomShield Collector running on PID {os.getpid()}[/]")
    console.print(f"[+] Output trace file: [cyan]{out_path}[/]")
    console.print(f"[+] Sandbox watch dir: [cyan]{args.watch_dir}[/]")

    # Initialize Storage (Block 9B) and Decision Engine (Block 8)
    storage = RansomShieldStorage()
    decision_engine = DecisionEngine(
        storage=storage,
        auto_mitigate=not args.no_mitigate,
        preferred_action=args.action
    )

    # Per-process sliding window state tracking (2.5s responsive window)
    pid_windows = defaultdict(lambda: {
        "timestamps": deque(),
        "writes": deque(),
        "renames": deque(),
        "deletes": deque(),
        "entropies": deque(),  # deque of (timestamp, entropy)
        "files": set(),
        "proc_name": "unknown",
        "last_alert_time": 0.0,
        "last_infer_time": 0.0,
        "cached_assessment": None,
        "current_cwc": 0,
        "has_net_connect": False,
    })

    event_counter = 0

    def process_normalized_event(ev: Dict[str, Any]):
        nonlocal out_file, event_counter
        event_counter += 1
        # Write to JSONL and flush periodically (every 50 events) to eliminate DrvFS fsync stall
        out_file.write(json.dumps(ev) + "\n")
        if event_counter % 50 == 0:
            out_file.flush()

        # Log to Persistent SQLite Store (Block 9B)
        storage.log_event(ev)

        # Update dashboard if active
        if dashboard:
            dashboard.push_event(ev)

        pid = int(ev.get("pid", 0))
        proc = str(ev.get("process", "unknown"))
        ev_type = str(ev.get("event_type", "OTHER"))
        path = ev.get("path")
        now = time.time()
        extra = ev.get("extra", {})
        entropy = float(extra.get("entropy", 0.0))

        # Ignore system processes and self
        if pid <= 1 or pid == os.getpid():
            return

        pdata = pid_windows[pid]
        pdata["proc_name"] = proc
        pdata["timestamps"].append(now)
        if path:
            pdata["files"].add(path)

        if ev_type == "FILE_WRITE":
            pdata["writes"].append(now)
            pdata["current_cwc"] += 1
            if entropy > 0:
                pdata["entropies"].append((now, entropy))
        elif ev_type == "FILE_READ":
            pdata["current_cwc"] = 0
        elif ev_type == "FILE_RENAME":
            pdata["renames"].append(now)
            old_p = extra.get("old_path")
            if old_p:
                pdata["files"].add(old_p)
        elif ev_type == "FILE_DELETE":
            pdata["deletes"].append(now)
        elif ev_type == "NET_CONNECT":
            pdata["has_net_connect"] = True

        # Purge older than 2.5 seconds (fast window for immediate detection & quick recovery to normal)
        cutoff = now - 2.5
        while pdata["timestamps"] and pdata["timestamps"][0] < cutoff:
            pdata["timestamps"].popleft()
        while pdata["writes"] and pdata["writes"][0] < cutoff:
            pdata["writes"].popleft()
        while pdata["renames"] and pdata["renames"][0] < cutoff:
            pdata["renames"].popleft()
        while pdata["deletes"] and pdata["deletes"][0] < cutoff:
            pdata["deletes"].popleft()
        while pdata["entropies"] and pdata["entropies"][0][0] < cutoff:
            pdata["entropies"].popleft()

        # Compute sliding rates (Block 4)
        write_count = len(pdata["writes"])
        rename_count = len(pdata["renames"])
        delete_count = len(pdata["deletes"])
        files_count = len(pdata["files"])
        time_span = max(0.5, min(2.5, now - pdata["timestamps"][0])) if pdata["timestamps"] else 2.5
        write_rate = write_count / time_span
        rename_rate = rename_count / time_span
        delete_rate = delete_count / time_span
        avg_entropy = sum(e for _, e in pdata["entropies"]) / len(pdata["entropies"]) if pdata["entropies"] else 0.0

        # Scan touched files for ransomware indicators
        dirs_touched = set()
        has_locked = 0
        has_note = 0
        for fpath in pdata["files"]:
            dirs_touched.add(str(Path(fpath).parent))
            if fpath.endswith(".locked") or fpath.endswith(".crypto") or fpath.endswith(".enc"):
                has_locked = 1
            if "HOW_TO_RESTORE" in fpath or "note" in fpath.lower() or "ransom" in fpath.lower():
                has_note = 1

        # Build Option B Live Window Feature Vector
        live_window_features = {
            "avg_entropy": avg_entropy,
            "write_rate": write_rate,
            "rename_rate": rename_rate,
            "delete_rate": delete_rate,
            "continuous_write_count": pdata.get("current_cwc", 0),
            "write_ratio": 1.0 if write_count > 0 else 0.0,
            "files_count": files_count,
            "directories_count": max(1, len(dirs_touched)),
            "has_locked_ext": has_locked,
            "has_ransom_note": has_note,
            "has_c2_connect": 1 if pdata.get("has_net_connect", False) else 0,
        }

        # Debounced Live Machine Learning Inference (Option B) - run at most once per 150ms per PID
        last_infer = pdata.get("last_infer_time", 0.0)
        should_infer = (now - last_infer >= 0.15) or has_locked or has_note or (write_count >= 8)

        if should_infer or not pdata.get("cached_assessment"):
            pdata["last_infer_time"] = now
            ai_assessment = live_predictor.predict_window(live_window_features)
            ai_assessment["pid"] = pid
            ai_assessment["process"] = proc
            pdata["cached_assessment"] = ai_assessment
        else:
            ai_assessment = pdata["cached_assessment"]

        if dashboard and should_infer:
            dashboard.push_ai_triage(ai_assessment)

        # Evaluate Deterministic Rules (Block 5A)
        rule_score = 0.0
        # R1: File Write Burst Rate / Count
        if write_rate >= 20.0 or write_count >= 12:
            rule_score += 35.0
        elif write_rate >= 8.0 or write_count >= 6:
            rule_score += 15.0

        # R2: Mass File Rename (Extension Tampering to .locked)
        if rename_rate >= 6.0 or rename_count >= 8:
            rule_score += 35.0
        elif rename_rate >= 2.5 or rename_count >= 4:
            rule_score += 15.0

        # R3: Shannon Entropy Spike (Encrypted Data Detection)
        if avg_entropy >= 7.0:
            rule_score += 35.0
        elif avg_entropy >= 6.0:
            rule_score += 15.0

        # R4: Directory Traversal Breadth
        if files_count >= 12:
            rule_score += 20.0

        # R5: Ransom Artifact Signatures
        if has_locked:
            rule_score += 35.0
        if has_note:
            rule_score += 25.0

        # Fused Threat Score (ML + Heuristic Rules)
        ml_prob = ai_assessment.get("probability", 0.0)
        ml_score = ml_prob * 100.0
        final_threat_score = max(rule_score, ml_score)
        if (ai_assessment.get("is_ransomware", False) and ml_prob >= 0.80) or has_locked:
            final_threat_score = max(final_threat_score, 95.0)

        threat_level_str = "CRITICAL" if final_threat_score >= 81.0 else ("HIGH" if final_threat_score >= 51.0 else "LOW")
        if dashboard:
            dashboard.update_process_threat(pid, final_threat_score, threat_level_str)

        # Trigger Decision Engine (Block 8) if High, Critical, or Malicious
        is_escalation = (final_threat_score >= 81.0 and pdata.get("last_level") != "CRITICAL")
        if (final_threat_score >= 51.0) and (is_escalation or (now - pdata["last_alert_time"] > 2.0)):
            pdata["last_alert_time"] = now
            pdata["last_level"] = threat_level_str

            score_id = storage.log_threat_score(
                pid=pid,
                process=proc,
                rule_score=rule_score,
                ai_score=ml_score,
                final_score=final_threat_score,
                threat_level=threat_level_str,
            )

            # Active Mitigation Action (SIGSTOP / SIGKILL + Quarantine)
            mitigation = decision_engine.evaluate_and_respond(
                pid=pid,
                process_name=proc,
                threat_score=final_threat_score,
                touched_files=list(pdata["files"]),
                score_id=score_id,
            )

            if dashboard and mitigation.action_taken != "LOG_ONLY":
                dashboard.push_mitigation_alert(asdict(mitigation))
            else:
                console.print(f"[bold red][MITIGATION] {mitigation.message}[/]")

    if args.dashboard:
        with Live(dashboard.render(), refresh_per_second=4, screen=False) as live:
            last_render = time.time()
            while proc.poll() is None or not event_queue.empty():
                while not event_queue.empty():
                    try:
                        line = event_queue.get_nowait()
                        raw_data = json.loads(line)
                        normalized = normalizer.normalize(raw_data)
                        process_normalized_event(normalized)
                    except Exception:
                        continue
                now_render = time.time()
                if now_render - last_render >= 0.2:
                    live.update(dashboard.render())
                    last_render = now_render
                time.sleep(0.01)
    else:
        while proc.poll() is None or not event_queue.empty():
            while not event_queue.empty():
                try:
                    line = event_queue.get_nowait()
                    raw_data = json.loads(line)
                    normalized = normalizer.normalize(raw_data)
                    process_normalized_event(normalized)
                    print(json.dumps(normalized))
                except Exception:
                    continue
            time.sleep(0.01)

    cleanup()


if __name__ == "__main__":
    main()
