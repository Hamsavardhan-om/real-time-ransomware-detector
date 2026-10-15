#!/usr/bin/env python3
"""
Benign User Workload Simulator.
Simulates everyday user actions: reading files, editing notes, creating a tar archive,
and fetching a safe web page. Operates with normal spacing to establish a clean baseline.
"""

import os
import time
import tarfile
import argparse
import urllib.request
from pathlib import Path

def run_benign(sandbox_dir: str = "/tmp/ransomware_sandbox"):
    sandbox = Path(sandbox_dir)
    if not sandbox.exists():
        print(f"[!] Sandbox directory {sandbox_dir} does not exist. Run setup_sandbox.py first.")
        return

    print(f"[*] Running benign user workload in {sandbox_dir}...")
    files = list(sandbox.rglob("file_*"))
    if not files:
        print("[!] No files found in sandbox.")
        return

    # 1. Normal file reading (reading 10 files with humane delay)
    read_count = 0
    for f in files[:10]:
        try:
            with open(f, "rb") as fp:
                _ = fp.read()
            read_count += 1
            time.sleep(0.05)
        except Exception:
            pass
    print(f"  [+] Read {read_count} files.")

    # 2. Normal file editing (appending notes)
    notes_file = sandbox / "Documents" / "file_0.txt"
    if not notes_file.exists():
        notes_file = files[0]
    with open(notes_file, "a", encoding="utf-8") as fp:
        fp.write("\n[BENIGN EDIT] Updated user note at " + str(time.time()))
    print(f"  [+] Appended note to {notes_file}.")
    time.sleep(0.1)

    # 3. Create a compressed backup archive
    archive_path = sandbox / "backup_user.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for f in files[:5]:
            tar.add(f, arcname=f.name)
    print(f"  [+] Created backup archive at {archive_path}.")
    time.sleep(0.1)

    # 4. Normal network connection (fetch example.com or DNS check)
    try:
        req = urllib.request.Request("http://1.1.1.1", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            _ = resp.read(128)
        print("  [+] Outbound web request completed.")
    except Exception:
        # Fallback to direct socket ping if no internet
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex(("1.1.1.1", 80))
            s.close()
            print("  [+] Fallback socket connect completed.")
        except Exception:
            pass

    print("[+] Benign workload completed successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox", default="/tmp/ransomware_sandbox", help="Sandbox path")
    args = parser.parse_args()

    run_benign(args.sandbox)
