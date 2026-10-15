#!/usr/bin/env python3
"""
RansomShield Event Replay Engine.

Replays recorded JSONL telemetry traces with high-fidelity timing simulation.
Allows Member 2 (Detection) and Member 3 (Evaluation) to repeatedly test and
benchmark algorithms against identical realistic event streams without rerunning workloads.
"""

import sys
import json
import time
import argparse
from pathlib import Path

def replay_trace(trace_file: str, speed: float = 1.0, filter_pid: int = 0):
    path = Path(trace_file)
    if not path.exists():
        print(f"[!] Trace file not found: {trace_file}", file=sys.stderr)
        sys.exit(1)

    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    ev = json.loads(line)
                    if filter_pid == 0 or ev.get("pid") == filter_pid:
                        events.append(ev)
                except json.JSONDecodeError:
                    continue

    if not events:
        print(f"[!] No valid events found in {trace_file}", file=sys.stderr)
        return

    # Ensure chronological order
    events.sort(key=lambda x: x.get("timestamp", 0.0))

    print(f"[*] Replaying {len(events)} events from {trace_file} (Speed: {speed}x)...", file=sys.stderr)

    prev_timestamp = None
    replayed_count = 0

    try:
        for ev in events:
            current_ts = ev.get("timestamp", 0.0)

            if prev_timestamp is not None and speed > 0:
                delta = current_ts - prev_timestamp
                if 0 < delta < 10.0: # Cap unrealistic gaps
                    sleep_time = delta / speed
                    time.sleep(sleep_time)

            prev_timestamp = current_ts
            # Print JSON line
            print(json.dumps(ev))
            sys.stdout.flush()
            replayed_count += 1
    except BrokenPipeError:
        pass

    print(f"[*] Replay complete. Total events emitted: {replayed_count}", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RansomShield Telemetry Replayer")
    parser.add_argument("trace_file", nargs="?", default=None, help="Path to events.jsonl file")
    parser.add_argument("--trace", dest="trace_flag", default=None, help="Alternative flag for path to events.jsonl file")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="Playback speed multiplier (e.g. 1.0 = real-time, 5.0 = 5x faster, 0 = instant)")
    parser.add_argument("--filter-pid", type=int, default=0,
                        help="Replay only events for this specific PID")
    args = parser.parse_args()

    trace_target = args.trace_file or args.trace_flag
    if not trace_target:
        parser.error("A trace file must be provided either as a positional argument or with --trace.")

    replay_trace(trace_target, args.speed, args.filter_pid)
