#!/usr/bin/env python3
"""
RansomShield: Real-Time & Pre-Execution Dual-Tier Ransomware Defense System.

Main unified orchestrator providing:
- Tier 1: Pre-Execution Sandbox Triage (Trained on real-world MLRan dataset, JNCA 2026)
- Tier 2: Real-Time Runtime Kernel Defense (Linux CO-RE eBPF sensor + Shannon Entropy)
- Benchmarking, training, and attack simulation tools.
"""

import sys
import os
import argparse
import subprocess
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

BANNER = r"""
  ____                               ____  _     _eld 
 |  _ \ __ _ _ __  ___  ___  _ __   / ___|| |__ (_) ___| | __| |
 | |_) / _` | '_ \/ __|/ _ \| '_ \  \___ \| '_ \| |/ _ \ |/ _` |
 |  _ < (_| | | | \__ \ (_) | | | |  ___) | | | | |  __/ | (_| |
 |_| \_\__,_|_| |_|___/\___/|_| |_| |____/|_| |_|_|\___|_|\__,_|
     Dual-Tier Ransomware Detection & Runtime Prevention
"""


def cmd_triage(args):
    """Tier 1 Pre-Execution Sandbox Triage."""
    from models.mlran_loader import MLRanLoader
    from models.mlran_predict import MLRanPredictor, print_triage_report

    loader = MLRanLoader()

    if args.list:
        print("\n" + "=" * 70)
        print(" MLRan Test Set Samples (Available for Triage Testing)")
        print("=" * 70)
        X_te, y_bin_te, y_typ_te, y_fam_te, ids_te = loader.load_test_data()
        print(" [RANSOMWARE SAMPLES]")
        ran_count = 0
        for i, sid in enumerate(ids_te):
            if y_bin_te[i] == 1 and ran_count < 5:
                fam = loader.family_map.get(int(y_fam_te[i]), "unknown")
                typ = loader.type_map.get(int(y_typ_te[i]), "unknown")
                print(f"   - Sample ID: {sid:<6} | Family: {fam:<16} | Type: {typ.upper()}")
                ran_count += 1

        print("\n [GOODWARE SAMPLES]")
        good_count = 0
        for i, sid in enumerate(ids_te):
            if y_bin_te[i] == 0 and good_count < 5:
                print(f"   - Sample ID: {sid:<6} | Category: Legitimate Application")
                good_count += 1
        print("=" * 70)
        print("Run triage on any ID using: python main.py triage --sample-id <ID>\n")
        return

    try:
        predictor = MLRanPredictor()
    except FileNotFoundError:
        print("\n[!] Trained Tier 1 models not found. Running training first...")
        from models.mlran_train import train_tier1_models
        train_tier1_models(loader, save_dir=PROJECT_ROOT / "models" / "saved" / "mlran")
        predictor = MLRanPredictor()

    result = predictor.triage_sample_id(args.sample_id, loader=loader)
    print_triage_report(result)


def cmd_train(args):
    """Re-trains Tier 1 MLRan models and displays benchmark scorecard."""
    from models.mlran_loader import MLRanLoader
    from models.mlran_train import train_tier1_models, print_scorecard

    loader = MLRanLoader()
    save_dir = PROJECT_ROOT / "models" / "saved" / "mlran"
    metadata = train_tier1_models(loader, save_dir=save_dir)
    print_scorecard(metadata)


def cmd_monitor(args):
    """Launches Unified Dual-Tier Platform: Tier 1 AI Triage + Tier 2 eBPF Real-Time Kernel Defense."""
    action = getattr(args, "action", "isolate")
    no_mitigate = getattr(args, "no_mitigate", False)
    dashboard = getattr(args, "dashboard", True)
    sample_id = getattr(args, "sample_id", "")

    if os.name == "nt":
        print("[!] Note: eBPF kernel tracing requires a Linux environment (Ubuntu / WSL2).")
        print("    Running via WSL...")
        wsl_root = subprocess.check_output(["wsl", "wslpath", "-a", str(PROJECT_ROOT)]).decode().strip()
        cmd = ["wsl", "sudo", "python3", f"{wsl_root}/collector/collector.py", "--watch-dir", args.watch_dir, "--action", action]
        if dashboard:
            cmd.append("--dashboard")
        else:
            cmd.append("--no-dashboard")
        if no_mitigate:
            cmd.append("--no-mitigate")
        if sample_id:
            cmd.extend(["--sample-id", sample_id])
        subprocess.run(cmd)
        return

    collector_script = PROJECT_ROOT / "collector" / "collector.py"
    cmd = [sys.executable, str(collector_script), "--watch-dir", args.watch_dir, "--action", action]
    if dashboard:
        cmd.append("--dashboard")
    else:
        cmd.append("--no-dashboard")
    if no_mitigate:
        cmd.append("--no-mitigate")
    if sample_id:
        cmd.extend(["--sample-id", sample_id])

    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    subprocess.run(cmd)


def cmd_detector(args):
    """Executes Behavioral Detection Engine on event trace."""
    beh_candidates = [
        Path("/mnt/c/Users/study/Downloads/behaviour/behviour-engine - Copy"),
        Path(r"C:\Users\study\Downloads\behaviour\behviour-engine - Copy"),
        PROJECT_ROOT / "datasets" / "behviour-engine",
    ]
    beh_dir = None
    for p in beh_candidates:
        if p.exists():
            beh_dir = p
            break

    if not beh_dir:
        print("[!] Error: Could not locate behavior engine directory.")
        return

    detector_script = beh_dir / "detector.py"
    trace = args.trace
    if not trace:
        default_trace = beh_dir / "datasets" / "sample_traces" / "ransomware_like_001.json"
        if default_trace.exists():
            trace = str(default_trace)
        else:
            trace = str(PROJECT_ROOT / "datasets" / "events.jsonl")

    cmd = [sys.executable, str(detector_script), trace]
    if getattr(args, "model", None):
        cmd.extend(["--model", args.model])
    subprocess.run(cmd)


def cmd_alerts(args):
    """Displays incident logs from the persistent storage database."""
    import time
    from engine.storage import RansomShieldStorage
    storage = RansomShieldStorage()
    alerts = storage.get_recent_alerts(limit=20)
    stats = storage.get_summary_stats()

    print("\n" + "=" * 80)
    print(f" RANSOMSHIELD DECISION ENGINE AUDIT LOG (Total Incidents: {stats['alerts']})")
    print("=" * 80)
    if not alerts:
        print(" [i] No security incidents or quarantined processes recorded yet.")
    else:
        for a in alerts:
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["ts"]))
            print(f" [{ts_str}] PID {a['pid']} ({a['process']}) -> Level: {a['level']} | Action: {a['action_taken']}")
            print(f"    Details: {a['details']}")
            print("-" * 80)
    print()


def cmd_isolate(args):
    """Manually isolates a suspicious process by PID (SIGSTOP)."""
    from engine.decision_engine import DecisionEngine
    de = DecisionEngine()
    if de.isolate_process(args.pid):
        print(f"[+] Successfully ISOLATED process PID {args.pid} (frozen in RAM via SIGSTOP).")
    else:
        print(f"[-] Could not isolate PID {args.pid} (process not found or permission denied).")


def cmd_kill(args):
    """Manually terminates a process by PID (SIGKILL)."""
    from engine.decision_engine import DecisionEngine
    de = DecisionEngine()
    if de.kill_process(args.pid):
        print(f"[+] Successfully TERMINATED process PID {args.pid} via SIGKILL.")
    else:
        print(f"[-] Could not kill PID {args.pid} (process not found or permission denied).")


def cmd_resume(args):
    """Resumes a suspended process (SIGCONT)."""
    from engine.decision_engine import DecisionEngine
    de = DecisionEngine()
    if de.resume_process(args.pid):
        print(f"[+] Successfully RESUMED process PID {args.pid} via SIGCONT.")
    else:
        print(f"[-] Could not resume PID {args.pid} (process not found or permission denied).")


def cmd_simulate(args):
    """Executes synthetic workloads in sandbox for live testing."""
    target_path = Path(args.target_dir)
    target_path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target_path, 0o777)
    except Exception:
        pass

    # Ensure mock files exist before running simulation
    has_files = any(target_path.rglob("file_*"))
    if not has_files:
        print(f"[*] Sandbox at {args.target_dir} is empty. Auto-populating with mock user files...")
        from workloads.setup_sandbox import setup_sandbox
        setup_sandbox(args.target_dir, num_folders=5, files_per_folder=10)

    if args.type == "ransomware":
        script = PROJECT_ROOT / "workloads" / "ransomware_simulator.py"
        print(f"[+] Running synthetic ransomware simulation in {args.target_dir}...")
    else:
        script = PROJECT_ROOT / "workloads" / "benign_workload.py"
        print(f"[+] Running benign user workload simulation in {args.target_dir}...")

    cmd = [sys.executable, str(script), "--sandbox", args.target_dir]
    subprocess.run(cmd)


def cmd_benchmark(args):
    """Generates verification scorecard across Tier 1, Tier 2, or both."""
    print(BANNER)
    print("=" * 80)
    print(" RANSOMSHIELD DUAL-TIER VERIFICATION SCORECARD")
    print("=" * 80)

    if args.tier in ["1", "both"]:
        from models.mlran_train import print_scorecard
        meta_file = PROJECT_ROOT / "models" / "saved" / "mlran" / "mlran_metadata.json"
        if meta_file.exists():
            import json
            with open(meta_file, "r") as f:
                meta = json.load(f)
            print_scorecard(meta)
        else:
            print("[!] Tier 1 metadata not found. Run `python main.py train` to generate benchmark.")

    if args.tier in ["2", "both"]:
        print("\n" + "=" * 80)
        print(" TIER 2: LINUX KERNEL eBPF TELEMETRY GROUND TRUTH VERIFICATION")
        print("=" * 80)
        val_script = PROJECT_ROOT / "validation" / "validate_telemetry.py"
        if os.name == "nt":
            wsl_root = subprocess.check_output(["wsl", "wslpath", "-a", str(PROJECT_ROOT)]).decode().strip()
            cmd = ["wsl", "sudo", "python3", f"{wsl_root}/validation/validate_telemetry.py"]
        else:
            cmd = ["sudo", sys.executable, str(val_script)]
        subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(
        description="RansomShield: Real-Time & Pre-Execution Dual-Tier Ransomware Defense System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Triage command (Tier 1)
    p_triage = subparsers.add_parser("triage", help="Tier 1: Pre-Execution Sandbox Triage (MLRan AI)")
    p_triage.add_argument("--sample-id", type=str, default="11027", help="Sample ID to inspect and classify")
    p_triage.add_argument("--list", action="store_true", help="List sample IDs from test set available to test")
    p_triage.add_argument("--model", type=str, choices=["lr", "rf"], default="lr", help="Model type to use")

    # Monitor command (Tier 2 + Tier 1 Unified)
    p_monitor = subparsers.add_parser("monitor", help="Unified Dual-Tier Platform: Tier 1 AI Triage + Tier 2 Kernel Defense")
    p_monitor.add_argument("--watch-dir", type=str, default="/tmp/ransomware_sandbox", help="Target watch directory")
    p_monitor.add_argument("--dashboard", action="store_true", default=True, help="Render Rich terminal dashboard")
    p_monitor.add_argument("--no-dashboard", dest="dashboard", action="store_false", help="Disable dashboard, print raw events to stdout")
    p_monitor.add_argument("--action", choices=["isolate", "kill"], default="isolate", help="Decision Engine action policy (default: isolate)")
    p_monitor.add_argument("--no-mitigate", action="store_true", help="Observe and log only without auto-mitigation")
    p_monitor.add_argument("--sample-id", type=str, default="", help="Optional MLRan sample ID to preload baseline Tier 1 triage")

    # Detector command (Behavioral engine from Member 2)
    p_detector = subparsers.add_parser("detector", help="Run offline behavioral detection on event trace JSON")
    p_detector.add_argument("trace", type=str, nargs="?", default="", help="Path to event trace JSON (default: sample trace)")
    p_detector.add_argument("--model", type=str, default="rf_v0.2", help="Model version (default: rf_v0.2)")

    # Alerts / Incident log command (Block 9B)
    p_alerts = subparsers.add_parser("alerts", help="View incident audit log and quarantined attacks from database")

    # Manual process control commands (Block 8)
    p_iso = subparsers.add_parser("isolate", help="Manually freeze a process by PID (SIGSTOP)")
    p_iso.add_argument("--pid", type=int, required=True, help="Target process PID")

    p_kill = subparsers.add_parser("kill", help="Manually terminate a process by PID (SIGKILL)")
    p_kill.add_argument("--pid", type=int, required=True, help="Target process PID")

    p_res = subparsers.add_parser("resume", help="Resume a suspended process by PID (SIGCONT)")
    p_res.add_argument("--pid", type=int, required=True, help="Target process PID")

    # Benchmark command
    p_bench = subparsers.add_parser("benchmark", help="Run full evaluation scorecard across tiers")
    p_bench.add_argument("--tier", choices=["1", "2", "both"], default="both", help="Which tier to benchmark")

    # Train command
    p_train = subparsers.add_parser("train", help="Train Tier 1 models on MLRan dataset")

    # Simulate command
    p_sim = subparsers.add_parser("simulate", help="Run benign or ransomware workload simulations")
    p_sim.add_argument("--type", choices=["ransomware", "benign"], default="ransomware", help="Workload type")
    p_sim.add_argument("--target-dir", type=str, default="/tmp/ransomware_sandbox", help="Sandbox target folder")

    args = parser.parse_args()

    if not args.command:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    if args.command == "triage":
        cmd_triage(args)
    elif args.command == "train":
        cmd_train(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "alerts":
        cmd_alerts(args)
    elif args.command == "isolate":
        cmd_isolate(args)
    elif args.command == "kill":
        cmd_kill(args)
    elif args.command == "resume":
        cmd_resume(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "detector":
        cmd_detector(args)


if __name__ == "__main__":
    main()
