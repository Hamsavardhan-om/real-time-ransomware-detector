# RansomShield: Real-Time Ransomware Detection System
## Module 1: Kernel eBPF Telemetry Sensor & Event Pipeline (50% Milestone)

[![Kernel: Linux 6.18+ CO-RE](https://img.shields.io/badge/Kernel-Linux%206.18%2B%20(BTF%2FCO--RE)-blue.svg)](https://kernel.org)
[![Telemetry: eBPF RingBuffer](https://img.shields.io/badge/Telemetry-eBPF%20RingBuffer-green.svg)](https://ebpf.io)
[![Accuracy: >=95% GroundTruth](https://img.shields.io/badge/Telemetry%20Integrity-100%25%20Verified-brightgreen.svg)]()
[![Integration: Member 2 Verified](https://img.shields.io/badge/Behavioral%20AI-100%25%20Compatible-blueviolet.svg)]()

---

## 1. System Architecture

RansomShield implements a high-performance, non-intrusive runtime telemetry pipeline built on Linux eBPF (Extended Berkeley Packet Filter). It continuously monitors kernel-level file system operations, process lifecycle state changes, and outbound network activity, streaming structured telemetry into Member 2's Behavioral AI Detection Engine.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            LINUX KERNEL SPACE                               │
│                                                                             │
│   tracepoint/syscalls/sys_enter_openat/openat2       (FILE_OPEN / CREATE)   │
│   tracepoint/syscalls/sys_enter_write / pwrite64     (FILE_WRITE)           │
│   tracepoint/syscalls/sys_enter_read                 (FILE_READ)            │
│   tracepoint/syscalls/sys_enter_rename / renameat2   (FILE_RENAME)          │
│   tracepoint/syscalls/sys_enter_unlink / unlinkat    (FILE_DELETE)          │
│   tracepoint/syscalls/sys_enter_close                (FILE_CLOSE)           │
│   tracepoint/syscalls/sys_enter_execve / exit        (PROCESS_EXEC / EXIT)  │
│   tracepoint/syscalls/sys_enter_connect              (NET_CONNECT)          │
│                                 │                                           │
│                 BPF Maps (fd_map, config_map)                               │
│                                 ▼                                           │
│                     eBPF Ring Buffer (1 MB)                                 │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ BPF ring_buffer__poll()
┌─────────────────────────────────▼───────────────────────────────────────────┐
│                        USERSPACE TELEMETRY LAYER                            │
│                                                                             │
│   1. Native C Loader (sensor_loader.c)                                      │
│      - Resolves process binary path via /proc/<pid>/exe                     │
│      - Resolves file descriptors into paths via BPF fd_map                  │
│      - Filters noise by directory subtree (--watch-dir)                     │
│      - Self-PID filtering via BPF config_map                                │
│                                 │                                           │
│   2. Python Normalizer & Shannon Entropy Engine (normalizer.py)             │
│      - Computes byte Shannon entropy (0.0 - 8.0) on file modifications      │
│      - Enforces strict Member 2 NormalizedEvent schema                      │
│                                 │                                           │
│   3. Rich Terminal Dashboard (dashboard.py)                                 │
│      - Real-time event throughput (ops/sec)                                 │
│      - Write burst & rename meters, process tree, color-coded event feeds   │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
┌────────────────────────────────┐                ┌───────────────────────────┐
│ Replay Engine (replay.py)      │                │ Member 2 AI Engine        │
│ - Deterministic playback       │                │ - Time Windows (5.0s)     │
│ - Configurable speed (1x-10x)  │───────────────▶│ - RansomFisher Features   │
│ - JSONL / JSON Trace Datasets  │                │ - 5 Deterministic Rules   │
│                                │                │ - ML Inference & Scoring  │
└────────────────────────────────┘                └───────────────────────────┘
```

---

## 2. Event Schema & Data Contract

All captured kernel operations are normalized to match Member 2's `NormalizedEvent` data contract:

```json
{
  "timestamp": 1789490220.615234,
  "pid": 30728,
  "ppid": 30680,
  "process": "python3",
  "exe": "/usr/bin/python3",
  "event_type": "FILE_WRITE",
  "path": "/tmp/ransomware_sandbox/Documents/file_0.docx",
  "bytes": 1024,
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "success": true,
  "extra": {
    "entropy": 7.9482
  }
}
```

### Captured Event Categories

| Event Type | Kernel Tracepoint / Probe | Telemetry Metadata Captured |
|:---|:---|:---|
| `FILE_OPEN` | `sys_enter_openat`, `sys_enter_openat2` | `path`, `flags`, `mode`, `pid`, `exe` |
| `FILE_READ` | `sys_enter_read` | `path` (via fd_map), `bytes`, `pid` |
| `FILE_WRITE` | `sys_enter_write`, `sys_enter_pwrite64` | `path` (via fd_map), `bytes`, `entropy`, `pid` |
| `FILE_CLOSE` | `sys_enter_close` | `path` (cleans up fd_map), `pid` |
| `FILE_RENAME`| `sys_enter_rename`, `renameat`, `renameat2` | `path` (new), `extra.old_path`, `pid` |
| `FILE_DELETE`| `sys_enter_unlink`, `sys_enter_unlinkat` | `path`, `pid` |
| `PROCESS_EXEC`| `sys_enter_execve` | `path` (binary), `pid`, `ppid`, `exe` |
| `PROCESS_EXIT`| `sched/sched_process_exit` | `pid`, `comm` |
| `NET_CONNECT`| `sys_enter_connect` | `dst_ip`, `dst_port`, `protocol` (TCP/UDP) |

---

## 3. Directory Structure

```
Real_time_ransomware_detection/
├── Makefile                          # Build automation for BPF bytecode and C loader
├── README.md                         # Architecture and run instructions
├── ebpf/
│   ├── vmlinux.h                     # Kernel BTF type definitions (generated via bpftool)
│   ├── event.h                       # Shared kernel/userspace event structures
│   ├── sensor.h                      # Tracepoint context definitions
│   ├── sensor.bpf.c                  # Core eBPF kernel program (CO-RE)
│   ├── sensor.bpf.o                  # Compiled BPF object bytecode
│   ├── sensor_loader.c               # Native C userspace ring buffer consumer
│   └── sensor_loader                 # Compiled native loader binary
├── collector/
│   ├── collector.py                  # Main CLI orchestrator & streaming pipeline
│   ├── normalizer.py                 # Shannon entropy calculator & schema normalizer
│   └── dashboard.py                  # Live Rich Terminal Dashboard (TUI)
├── schema/
│   ├── __init__.py                   # Package initialization
│   └── event_schema.py               # NormalizedEvent and EventType dataclass models
├── replay/
│   └── replay.py                     # Deterministic trace replayer with speed control
├── workloads/
│   ├── setup_sandbox.py              # Mock multi-directory document generator
│   ├── benign_workload.py            # Real-world benign user activity simulator
│   └── ransomware_simulator.py       # High-fidelity synthetic AES-256 ransomware
├── datasets/
│   ├── benign_events.jsonl           # Captured streaming trace (benign)
│   ├── benign_events.json            # Member 2 formatted trace (benign)
│   ├── benign_results.json           # Member 2 detection output (benign)
│   ├── ransomware_events.jsonl       # Captured streaming trace (ransomware)
│   ├── ransomware_events.json        # Member 2 formatted trace (ransomware)
│   └── ransomware_results.json       # Member 2 detection output (ransomware)
└── validation/
    ├── validate_telemetry.py         # Ground truth benchmark scorecard (>=95% test)
    └── run_member2_integration.py    # End-to-end integration benchmark with Member 2
```

---

## 4. Prerequisites & Build Instructions

### Prerequisites (Ubuntu / WSL2)
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic bpftool python3 python3-pip
pip3 install rich cryptography psutil scikit-learn xgboost joblib numpy scipy
```

### Build eBPF Bytecode & Loader
```bash
make clean
make
```

---

## 5. How to Run

### A. Live Interactive Terminal Dashboard
Starts the eBPF kernel sensor and opens a live Rich TUI dashboard displaying real-time events, write rates, rename bursts, and active process telemetry:
```bash
sudo python3 collector/collector.py --watch-dir /tmp/ransomware_sandbox --dashboard
```

### B. Run Ground Truth Telemetry Benchmark
Executes a strictly controlled sequence of 30 writes, 30 renames, 30 deletes, and outbound connections, verifying $\ge 95\%$ accuracy against ground truth:
```bash
sudo python3 validation/validate_telemetry.py
```
**Scorecard Result**:
- `FILE_WRITE`: 30/30 (100% exact match)
- `FILE_RENAME`: 30/30 (100% exact match)
- `FILE_DELETE`: 30/30 (100% exact match)
- `NET_CONNECT`: 2/2 (100% exact match)
- `Bytes Written`: 3,960 / 3,960 bytes (100.0% exact match)

### C. Run End-to-End Member 2 AI Integration Test
Executes both benign and ransomware workloads under live eBPF monitoring, passes captured telemetry into Member 2's Behavioral Detection Engine, and verifies classification:
```bash
sudo python3 validation/run_member2_integration.py
```

### D. Replay Captured Traces
Replay saved traces with realistic temporal delay or accelerated speed:
```bash
# Real-time replay (1.0x)
python3 replay/replay.py datasets/ransomware_events.jsonl --speed 1.0

# Accelerated replay (5.0x)
python3 replay/replay.py datasets/ransomware_events.jsonl --speed 5.0

# Instant replay (0 = no sleep)
python3 replay/replay.py datasets/ransomware_events.jsonl --speed 0
```

---

## 6. Verification & Detection Results

| Workload Scenario | Rule Score | ML Score | Fused Threat Score | Member 2 Classification | Detection Status |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Benign Workload** (Word editing, tar, web) | **0.0 / 100** | 0.0 / 100 | **0.0 / 100** | `BENIGN` | **PERFECT PASS** |
| **Synthetic Ransomware** (AES-256 burst + C2) | **100.0 / 100** | 70.0 / 100 | **75.0 / 100** | `RANSOMWARE_LIKE` | **PERFECT PASS** |

### Triggered Behavioral Rules (Member 2 Engine):
1. **R1: High File Write Frequency** (Write rate: 121.2 ops/s $\ge$ 30.0/s) — **Triggered** (+25 pts)
2. **R2: High File Rename Frequency** (Rename rate: 24.0 ops/s $\ge$ 10.0/s) — **Triggered** (+25 pts)
3. **R3: Bulk I/O Write Ratio** (Bulk Ratio: 0.99, Write Ratio: 0.91 $\ge$ 0.70) — **Triggered** (+20 pts)
4. **R4: High Continuous Write Count** (CWC: 5 consecutive bulk writes $\ge$ 3) — **Triggered** (+15 pts)
5. **R5: Broad Directory Traversal** (Modified 246 files across 8 directories) — **Triggered** (+15 pts)
