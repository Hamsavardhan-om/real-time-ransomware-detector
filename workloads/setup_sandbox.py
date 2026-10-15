#!/usr/bin/env python3
"""
Sets up a realistic sandbox folder structure with mock user files for testing.
"""

import os
import shutil
import argparse
from pathlib import Path

SAMPLE_EXTENSIONS = [
    (".pdf", "PDF file header simulation data: %PDF-1.4 ... confidential customer report 2026 ..."),
    (".docx", "DOCX standard document contents: Executive project roadmap and architectural breakdown..."),
    (".xlsx", "XLSX spreadsheet data: Quarterly financial balance sheets, department budget records..."),
    (".txt", "Meeting notes: Discussing eBPF pipeline integration and model scoring heuristics..."),
    (".jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 200 + b"Binary raw image contents JPEG"),
]

def setup_sandbox(sandbox_dir: str = "/tmp/ransomware_sandbox", num_folders: int = 5, files_per_folder: int = 10):
    sandbox = Path(sandbox_dir)
    if sandbox.exists():
        shutil.rmtree(sandbox)
    sandbox.mkdir(parents=True, exist_ok=True)

    folder_names = ["Documents", "Personal", "Finance", "Projects", "Archives"]
    created_files = []

    for i in range(num_folders):
        folder_name = folder_names[i % len(folder_names)] + (f"_{i}" if i >= len(folder_names) else "")
        dir_path = sandbox / folder_name
        dir_path.mkdir(parents=True, exist_ok=True)

        for j in range(files_per_folder):
            ext, content = SAMPLE_EXTENSIONS[j % len(SAMPLE_EXTENSIONS)]
            filename = f"file_{j}{ext}"
            file_path = dir_path / filename

            if isinstance(content, str):
                file_path.write_text(content * 64, encoding="utf-8")
            else:
                file_path.write_bytes(content * 32)

            created_files.append(str(file_path))

    print(f"[+] Successfully populated sandbox at '{sandbox_dir}' with {len(created_files)} mock files across {num_folders} directories.")
    return created_files

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox", default="/tmp/ransomware_sandbox", help="Sandbox path")
    parser.add_argument("--folders", type=int, default=5, help="Number of subdirectories")
    parser.add_argument("--files", type=int, default=10, help="Files per folder")
    args = parser.parse_args()

    setup_sandbox(args.sandbox, args.folders, args.files)
