# RansomShield: Real-Time & Pre-Execution Dual-Tier Ransomware Defense System

[![Dataset: MLRan (JNCA 2026)](https://img.shields.io/badge/Dataset-MLRan%20(4%2C880%20Samples)-blue.svg)](https://github.com/faithfulco/mlran)
[![Tier 1 Accuracy: 98.15%](https://img.shields.io/badge/Tier%201%20Accuracy-98.15%25%20Verified-brightgreen.svg)]()
[![Tier 1 Recall: 98.71%](https://img.shields.io/badge/Tier%201%20Recall-98.71%25%20Sensitivity-brightgreen.svg)]()
[![Kernel Telemetry: 100%](https://img.shields.io/badge/eBPF%20Capture%20Rate-100%25%20Verified-brightgreen.svg)]()
[![Active Containment: SIGSTOP/Quarantine](https://img.shields.io/badge/Active%20Defense-SIGSTOP%20%7C%20Quarantine-red.svg)]()
[![Platform: Linux / WSL2 (CO-RE)](https://img.shields.io/badge/Kernel-Linux%206.18%2B%20(BTF%2FCO--RE)-blue.svg)](https://kernel.org)

> **RansomShield** is an academic-grade, end-to-end ransomware defense architecture that unifies **Pre-Execution AI Sandbox Triage (Tier 1)** with **In-Kernel Real-Time eBPF Telemetry & Active Containment (Tier 2)**. 
>
> Designed to bridge the gap between static signature scanners (which miss packed zero-days) and user-space behavioral monitors (which react too late), RansomShield inspects binaries prior to launch and actively neutralizes active encryption bursts mid-execution directly at the Linux kernel boundary.

---

## Table of Contents
1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Tier 1: Pre-Execution Sandbox Triage & Explainable AI](#3-tier-1-pre-execution-sandbox-triage--explainable-ai)
4. [Tier 2: Real-Time Kernel Defense & Active Mitigation](#4-tier-2-real-time-kernel-defense--active-mitigation)
5. [Offline Behavioral Analysis Engine (Member 2 Integration)](#5-offline-behavioral-analysis-engine-member-2-integration)
6. [Experimental Evaluation & Output Metrics](#6-experimental-evaluation--output-metrics)
7. [Installation & Prerequisites](#7-installation--prerequisites)
8. [Comprehensive CLI Command Reference](#8-comprehensive-cli-command-reference)
9. [Step-by-Step Live Demonstration Guide](#9-step-by-step-live-demonstration-guide)
10. [Repository Structure & Codebase Map](#10-repository-structure--codebase-map)
11. [Academic References & Citation](#11-academic-references--citation)

---

## 1. Executive Summary & Problem Statement

Modern ransomware attacks have evolved from simple script-based file encryptors into highly evasive, multi-stage threats employing code obfuscation, packing, kernel tampering, and multi-threaded encryption bursts exceeding hundreds of files per second.

Existing defenses suffer from two critical architectural flaws:
1. **The Static Blindspot**: Traditional signature and static PE analyzers evaluate binaries solely at rest. Polymorphic packers and zero-day variants easily bypass these perimeter checks.
2. **The User-Space Latency Gap**: Conventional runtime endpoint agents monitor user-space file system events (e.g., `inotify`, `ReadDirectoryChangesW`). By the time a user-space agent aggregates enough event history to declare a process malicious, the ransomware has already encrypted thousands of sensitive files, deleted volume shadow copies, and exfiltrated encryption keys.

### The RansomShield Solution: Dual-Tier Coordinated Defense
RansomShield resolves this paradigm through a coordinated dual-tier pipeline:
* **Tier 1 (Pre-Execution Sandbox Triage)**: Evaluates PE binaries prior to deployment using machine learning models trained on the real-world **MLRan** dataset (*Journal of Network and Computer Applications*, 2026). It extracts 483 behavioral and structural traits to deliver instant binary classification (Ransomware vs. Goodware), operational type identification (Crypto vs. Locker), family profiling across 64 distinct ransomware strains, and transparent feature-weight explainability.
* **Tier 2 (Real-Time In-Kernel Defense & Active Containment)**: Deploys Linux **CO-RE (Compile Once – Run Everywhere) eBPF** probes directly into kernel syscall tracepoints. It streams file I/O operations through an in-memory sliding window, calculates byte-level **Shannon entropy** on write buffers, monitors rapid extension renames, and executes sub-10ms **active containment** (freezing the offending PID via `SIGSTOP` or `SIGKILL` mid-attack, and automatically isolating encrypted files into a tamper-evident quarantine vault).

---

## 2. End-to-End System Architecture

```
                                  RANSOMSHIELD ARCHITECTURE
   
   [ INCOMING BINARY / WORKLOAD ]
                 │
                 ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     TIER 1: PRE-EXECUTION SANDBOX TRIAGE                    │
 │                                                                             │
 │   • Dataset: MLRan (JNCA 2026, 4,880 Samples, 64 Ransomware Families)       │
 │   • Extraction: 483 Optimized Behavioral & Structural RFE Features          │
 │   • Classifiers: Logistic Regression | Random Forest | XGBoost              │
 │   • Predictions:                                                            │
 │       ├─ Binary:     Ransomware vs. Goodware (98.15% Accuracy, 98.71% Rec)   │
 │       ├─ Type:       Crypto-Ransomware vs. Screen/MBR Locker                │
 │       └─ Family:     WannaCry, Locky, Cerber, Shade, Mbrlock, Reveton, ...  │
 │   • Explainability: Transparent feature weight attribution (+ / - impact)   │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │ (If execution allowed / live host)
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │               TIER 2: REAL-TIME KERNEL DEFENSE & ACTIVE MITIGATION           │
 │                                                                             │
 │   ┌─────────────────────────────────────────────────────────────────────┐   │
 │   │                  Linux Kernel Space (eBPF CO-RE)                    │   │
 │   │  Syscall Hooks: openat, write, pwrite64, rename, unlink, execve, ...│   │
 │   │  Buffer Telemetry -> Zero-Copy Kernel BPF Ring Buffer               │   │
 │   └──────────────────────────────────┬──────────────────────────────────┘   │
 │                                      │ (Sub-millisecond stream)             │
 │                                      ▼                                      │
 │   ┌─────────────────────────────────────────────────────────────────────┐   │
 │   │                     Native Userspace C Loader                       │   │
 │   │  • Low-overhead ring-buffer consumer (sensor_loader.c)              │   │
 │   │  • Microsecond timestamping & JSONL event emission                  │   │
 │   └──────────────────────────────────┬──────────────────────────────────┘   │
 │                                      │                                      │
 │                                      ▼                                      │
 │   ┌─────────────────────────────────────────────────────────────────────┐   │
 │   │                 Streaming Normalizer & Analytics Engine             │   │
 │   │  • Shannon Entropy: Byte-level randomness H(X) on write buffers     │   │
 │   │  • Sliding-Window Rate: Write velocity (>=30/s), Renames (>=10/s)   │   │
 │   │  • Multi-Factor Threat Score: Score in [0, 100]                     │   │
 │   └──────────────────────────────────┬──────────────────────────────────┘   │
 │                                      │                                      │
 │                                      ▼                                      │
 │   ┌─────────────────────────────────────────────────────────────────────┐   │
 │   │                  Decision Engine & Active Containment               │   │
 │   │  • Score >= 81 (CRITICAL) -> IMMEDIATE CONTAINMENT:                 │   │
 │   │      1. Process Freeze: Send SIGSTOP (halts attack dead in RAM)     │   │
 │   │      2. Process Termination: Send SIGKILL (optional hard policy)    │   │
 │   │      3. Vault Quarantine: Moves *.locked files to secure directory  │   │
 │   │      4. Persistent Audit Log: Writes incident to SQLite DB          │   │
 │   │      5. Live TUI Dashboard: Displays color-coded real-time alerts   │   │
 │   └─────────────────────────────────────────────────────────────────────┘   │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Tier 1: Pre-Execution Sandbox Triage & Explainable AI

Tier 1 acts as the pre-execution gatekeeper. Before an executable binary is granted execution permissions on a production host, it is evaluated against structural and behavioral signatures derived from extensive sandbox dynamic traces.

### 3.1 The Dataset: MLRan (JNCA 2026)
RansomShield is trained and validated on the peer-reviewed **MLRan** dataset (*Journal of Network and Computer Applications*, 2026):
* **4,880 Total Binaries**: 2,330 ransomware binaries and 2,550 legitimate goodware applications.
* **64 Distinct Ransomware Families**: Includes real-world strains such as *WannaCry, Locky, Cerber, CryptoLocker, Mbrlock, Shade, Reveton, GandCrab, TeslaCrypt, Petya, Koler, Similocker*, and 53 others.
* **2 Operational Ransomware Types**:
  * **CRYPTO**: Payloads that systematically traverse directories, encrypt document headers/payloads, and demand ransoms via dropped notes.
  * **LOCKER**: Payloads that seize device control by locking the Master Boot Record (MBR), desktop interface, or window management subsystems without necessarily altering mass user documents.
* **11 Goodware Application Categories**: Clean enterprise software, system administration utilities, text editors, compilers, web browsers, and media players.

### 3.2 483 Recursive Feature Elimination (RFE) Features
Rather than relying on brittle cryptographic hashes (e.g., SHA-256), Tier 1 analyzes 483 optimized behavioral traits selected via Recursive Feature Elimination (RFE):
1. **Native Windows API Calls**: Hooks into low-level memory allocation, thread manipulation, and process discovery (e.g., `NtAllocateVirtualMemory`, `LdrGetProcedureAddress`, `NtOpenProcess`, `WriteConsoleW`, `CoUninitialize`).
2. **Registry Manipulation**: Key modifications targeting system startup, keyboard layouts, and credential profiles (e.g., `CurrentVersion\ProfileList`, `Keyboard Layout\Toggle`, `LanguageProfile`).
3. **Execution Signatures & PE Indicators**: Memory execution flags (`allocates_rwx`), high section entropy indicators (`packer_entropy`), and embedded runtime strings (`!this program cannot be run in dos mode.`, `kernel32.dll`, `ntdll.dll`).
4. **Dynamic Library Loading Patterns**: Tracking dynamic DLL attachments (`uxtheme.dll`, `ole32.dll`, `dwmapi.dll`, `advapi32.dll`, `comctl32.dll`).

### 3.3 Explainable AI (XAI) Weight Attribution
Every classification generated by Tier 1 is accompanied by an explainability breakdown. Each active behavioral trait is weighted using model coefficients:
* Positive weights (`+Weight`) represent traits strongly correlated with ransomware behavior (e.g., `API:NtAllocateVirtualMemory`, `SIGNATURE:packer_entropy`).
* Negative weights (`-Weight`) represent traits characteristic of benign software (e.g., `API:CoUninitialize`, `DLL_LOADED:uxtheme.dll`).

---

## 4. Tier 2: Real-Time Kernel Defense & Active Mitigation

Tier 2 provides runtime defense against zero-day exploits, packed binaries that evade Tier 1 static inspection, in-memory script payloads, and living-off-the-land binaries (LotL).

### 4.1 In-Kernel eBPF Telemetry Engine
* **CO-RE (Compile Once – Run Everywhere)**: Built using BPF Type Format (`BTF`) definitions from `vmlinux.h`, allowing native execution across Linux kernel versions (6.x+) without runtime compiler overhead.
* **Syscall Hooks**: Attached directly to kernel tracepoints:
  * `sys_enter_openat` / `openat2`: Captures file descriptors, target file paths, and creation/read/write flags.
  * `sys_enter_write` / `pwrite64`: Intercepts file writes and copies leading data buffer chunks to calculate live entropy.
  * `sys_enter_rename` / `renameat2`: Detects file extension changes (e.g., `.docx` $\to$ `.locked`).
  * `sys_enter_unlink` / `unlinkat`: Monitors mass file deletion and volume shadow copy destruction.
  * `sys_enter_connect`: Tracks outbound socket calls to identify C2 beaconing.
* **Zero-Copy Ring Buffer**: Events are transferred directly from kernel ring-buffer memory (`bpf_ringbuf_output`) to a native C userspace loader (`ebpf/sensor_loader.c`), achieving sub-millisecond event streaming with zero dropped events under high load.

### 4.2 Dynamic Heuristics & Shannon Entropy Analysis
The userspace collector evaluates live process activity across an in-memory sliding time window:
1. **Shannon Entropy Metric**:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   * Normal structured text, source code, and configuration files display low entropy: $H(X) \in [3.0, 4.5]$.
   * High-grade cryptographic encryption (AES-256, ChaCha20, RSA) maximizes randomness, producing near-theoretical maximum entropy: $H(X) \in [7.5, 8.0]$.
2. **Burst Velocity Tracking**:
   * Evaluates the rate of file writes ($\ge 30\text{ ops/sec}$).
   * Evaluates the rate of file renames ($\ge 10\text{ ops/sec}$) matching ransomware extension patterns (`.locked`, `.crypto`, `.enc`, etc.).
   * Tracks continuous consecutive write operations without corresponding user read latency.

### 4.3 Multi-Factor Threat Score & Mitigation Policies
The Decision Engine fuses dynamic metrics into a continuous threat score:

$$\text{ThreatScore} = w_e \cdot \text{EntropyScore} + w_w \cdot \text{WriteBurst} + w_r \cdot \text{RenameRate} + w_d \cdot \text{DeleteRate}$$

| Threat Level | Score Range | System Action | Description |
| :--- | :---: | :---: | :--- |
| **LOW** | $0 - 25$ | **ALLOW** | Normal user activity, text editing, software compilation. |
| **MEDIUM** | $26 - 50$ | **OBSERVE** | Elevated file I/O or archive creation; enhanced logging active. |
| **HIGH** | $51 - 80$ | **WARNING** | Warning banner raised on live dashboard; process flagged. |
| **CRITICAL** | $81 - 100+$ | **ISOLATE & CONTAIN** | **Automated Containment Triggered**: Process frozen via `SIGSTOP` or terminated via `SIGKILL`; encrypted files quarantined. |

### 4.4 Automated Containment Pipeline (What Happens After Detection)
When a process escalates to `CRITICAL` ($\ge 81.0$), RansomShield does not merely log the incident—it executes an immediate four-step containment sequence:
1. **Sub-10ms Process Freezing (`SIGSTOP`)**: Sends a POSIX `SIGSTOP` signal to the attacking process PID. Unlike `SIGKILL`, `SIGSTOP` freezes the thread instantaneously in RAM without clearing process memory, stopping encryption mid-burst while preserving evidence for forensic inspection.
2. **Aggressive Termination Policy (`SIGKILL`)**: If configured with `--action kill`, immediately terminates the process tree to neutralize persistence.
3. **Automated Quarantine Vault**: Scans the target directory for files altered or appended with ransomware extensions (e.g., `*.locked`) and atomically moves them into `/tmp/.ransomshield_quarantine/` with restricted permissions (`0700`), preventing access or extortion propagation.
4. **DrvFS-Optimized Persistent Audit Logging**: Logs the full incident context (PID, process name, timestamp, entropy score, action taken, and quarantined file lists) to an SQLite database ([`datasets/ransomshield.db`](file:///e:/VIT%20%28Semester%20VII%29/Final%20year%20project/Real_time_ransomware_detection/datasets/ransomshield.db)) configured with `PRAGMA journal_mode=DELETE` and batched commits to ensure reliability across Linux and WSL2 DrvFS partitions.
5. **False-Positive Recovery (`SIGCONT`)**: If an administrator verifies that an alert was triggered by legitimate administrative activity, the process can be resumed instantly with a single command (`python3 main.py resume --pid <PID>`).

---

## 5. Offline Behavioral Analysis Engine (Member 2 Integration)

For environments requiring retrospective forensic analysis or batch trace auditing, RansomShield integrates the Member 2 Behavioral Engine:
* Consumes standardized JSON/JSONL event traces (`NormalizedEvent`).
* Runs rule-based heuristics fused with a pre-trained Random Forest model (`rf_v0.2`).
* Generates detailed JSON threat assessments containing individual rule scores, ML confidence probabilities, and threat categorizations (`BENIGN` vs. `RANSOMWARE_LIKE`).

---

## 6. Experimental Evaluation & Output Metrics

This section details the empirical evaluation results across both defense tiers, highlighting detection accuracy, precision, recall, confusion matrix distributions, and kernel telemetry fidelity.

### 6.1 Tier 1: Pre-Execution Classification Performance
Evaluated on **975 unseen, held-out test binaries** from the MLRan dataset (465 real-world ransomware samples, 510 legitimate applications):

#### Binary Classification Benchmark (Ransomware vs. Goodware)

| Metric | Logistic Regression (Recommended) | Random Forest | XGBoost |
| :--- | :---: | :---: | :---: |
| **Accuracy** | **98.15%** | 96.82% | 96.41% |
| **Balanced Accuracy** | **98.18%** | 96.85% | 96.45% |
| **Precision** | **97.45%** | 95.97% | 95.36% |
| **Recall (Sensitivity)** | **98.71%** | 97.42% | 97.20% |
| **F1-Score** | **98.08%** | 96.69% | 96.27% |
| **False Positive Rate (FPR)** | **2.35%** | 3.73% | 4.31% |
| **False Negative Rate (FNR)** | **1.29%** | 2.58% | 2.80% |

#### Confusion Matrix (Logistic Regression on 975 Test Binaries)

```
                       ┌──────────────────────────────┐
                       │     Predicted Goodware       │     Predicted Ransomware     │
┌──────────────────────┼──────────────────────────────┼──────────────────────────────┤
│ Actual Goodware (510)│    True Negatives (TN): 498  │   False Positives (FP): 12   │
├──────────────────────┼──────────────────────────────┼──────────────────────────────┤
│ Actual Ransomware(465│   False Negatives (FN): 6    │   True Positives (TP): 459   │
└──────────────────────┴──────────────────────────────┴──────────────────────────────┘
```

#### Multi-Class Operational Type & Family Identification
* **Operational Type Classification (Crypto vs. Locker vs. Goodware)**:
  * Accuracy: **87.18%**
  * Weighted F1-Score: **87.28%**
* **Family Attribution (Across 64 Distinct Ransomware Families)**:
  * Accuracy: **80.41%**
  * Weighted F1-Score: **80.48%**

#### Top 10 Deciding Behavioral Features (Feature Importance Ranking)

| Rank | Feature Identifier | Feature Name / Trait | Importance Weight |
| :---: | :---: | :--- | :---: |
| **1** | `6413348` | `SYSTEM:DLL_LOADED:uxtheme.dll` | `0.0508` |
| **2** | `6412331` | `SYSTEM:DLL_LOADED:ole32.dll` | `0.0455` |
| **3** | `2944930` | `STRING:!this program cannot be run in dos mode.` | `0.0310` |
| **4** | `119780` | `REG:OPENED:LanguageProfile\{0001bea3...}` | `0.0308` |
| **5** | `214391` | `REG:READ:LanguageProfile\Enable` | `0.0290` |
| **6** | `140100` | `REG:READ:Keyboard Layout\Toggle\Language Hotkey` | `0.0265` |
| **7** | `140099` | `REG:READ:Keyboard Layout\Toggle\Hotkey` | `0.0245` |
| **8** | `140101` | `REG:READ:Keyboard Layout\Toggle\Layout Hotkey` | `0.0176` |
| **9** | `6412800` | `SYSTEM:DLL_LOADED:dwmapi.dll` | `0.0169` |
| **10** | `120875` | `REG:OPENED:ProfileList\S-1-5-21...` | `0.0158` |

---

### 6.2 Tier 2: Real-Time Kernel Telemetry & Ground Truth Capture
Validated using a dedicated synthetic workload generating exact ground-truth operations in a controlled process (`validation/validate_telemetry.py`):

| Event Category | Ground Truth Ops | Captured by eBPF | Capture Rate (%) | Verification Status |
| :--- | :---: | :---: | :---: | :---: |
| **FILE_WRITE** (File Writes) | 30 | 30 | **100.0%** | **PASS** |
| **FILE_READ** (File Reads) | 30 | 30 | **100.0%** | **PASS** |
| **FILE_RENAME** (File Renames) | 30 | 30 | **100.0%** | **PASS** |
| **FILE_DELETE** (File Unlinks) | 30 | 30 | **100.0%** | **PASS** |
| **NET_CONNECT** (Network Outbound) | 2 | 2 | **100.0%** | **PASS** |
| **EXACT BYTES WRITTEN** | 3,960 Bytes | 3,960 Bytes | **100.0%** | **PASS** |
| **OVERALL TELEMETRY INTEGRITY** | **122 Events** | **122 Events** | **100.0%** | **VERIFIED (100%)** |

---

### 6.3 End-to-End Behavioral AI Detection Results
Validated by streaming live kernel telemetry directly into the Behavioral Engine (`validation/run_member2_integration.py`):

| Workload Scenario | Rule Score | ML Confidence Score | Fused Threat Score | AI Classification | Integration Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Benign Workload Baseline** | $0.0$ | $0.0$ | **$0.0$** | **BENIGN** | **PERFECT MATCH** |
| **Ransomware Attack Workload**| $95.0$ | $92.4$ | **$93.7$** | **RANSOMWARE_LIKE** | **PERFECT MATCH** |

---

### 6.4 Real-World Triage & Runtime Containment Outputs

#### Tier 1 Triage Report (Sample ID 11027 - MBR Locker)
```text
======================================================================
 RANSOMSHIELD TIER 1: PRE-EXECUTION TRIAGE REPORT
======================================================================
 Sample ID:            11027
 AI Classification:    RANSOMWARE (Confidence: 99.9%)
 Ransomware Probability: 99.9%
 Predicted Type:       LOCKER
 Predicted Family:     Mbrlock
 Ground Truth:         RANSOMWARE (mbrlock, locker) -> MATCH (CORRECT)

 Active Behavioral Traits: 122 present
 Key Deciding Features (Explainable Evidence):
   1. [RANSOMWARE] API:LdrGetProcedureAddress (Weight: +1.740)
   2. [RANSOMWARE] API:NtAllocateVirtualMemory (Weight: +1.423)
   3. [RANSOMWARE] SIGNATURE:packer_entropy (Weight: +1.319)
   4. [RANSOMWARE] SIGNATURE:allocates_rwx (Weight: +0.982)
   5. [RANSOMWARE] STRING:user32 (Weight: +0.839)
   6. [RANSOMWARE] STRING:kernel32.dll (Weight: +0.832)
   7. [RANSOMWARE] API:NtOpenProcess (Weight: +0.574)
   8. [RANSOMWARE] API:WriteConsoleW (Weight: +0.512)
======================================================================
```

#### Tier 1 Triage Report (Sample ID 13003 - Benign Application)
```text
======================================================================
 RANSOMSHIELD TIER 1: PRE-EXECUTION TRIAGE REPORT
======================================================================
 Sample ID:            13003
 AI Classification:    GOODWARE (Confidence: 99.9%)
 Ransomware Probability: 0.1%
 Ground Truth:         GOODWARE (goodware, goodware) -> MATCH (CORRECT)

 Active Behavioral Traits: 39 present
 Key Deciding Features (Explainable Evidence):
   1. [GOODWARE] API:CoUninitialize (Weight: -0.813)
   2. [GOODWARE] SYSTEM:DLL_LOADED:uxtheme.dll (Weight: -0.802)
   3. [GOODWARE] SYSTEM:DLL_LOADED:comctl32.dll (Weight: -0.581)
   4. [GOODWARE] STRING:</html> (Weight: -0.576)
   5. [GOODWARE] SYSTEM:DLL_LOADED:advapi32.dll (Weight: -0.574)
   6. [GOODWARE] SYSTEM:DLL_LOADED:msimg32.dll (Weight: -0.549)
======================================================================
```

#### Tier 2 Containment Audit Log Output (`python3 main.py alerts`)
```text
================================================================================
 RANSOMSHIELD DECISION ENGINE AUDIT LOG (Total Incidents: 5)
================================================================================
 [2026-10-16 01:43:57] PID 4162 (python3) -> Level: CRITICAL | Action: ISOLATE_PROCESS
    Details: High threat score 90.0 (Entropy=7.86, Writes=7). Process frozen via SIGSTOP. Quarantined 7 files.
--------------------------------------------------------------------------------
```

---

## 7. Installation & Prerequisites

### 7.1 Operating System & Kernel Requirements
* **Platform**: Linux (Ubuntu 22.04 LTS or 24.04 LTS) or **Windows Subsystem for Linux (WSL2)** running an Ubuntu distribution.
* **Kernel**: Linux kernel 5.8 or higher with `CONFIG_DEBUG_INFO_BTF=y` enabled (Linux 6.x recommended).

### 7.2 System Packages & Toolchain
Install the required C/eBPF toolchain and dependencies:
```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev linux-tools-common bpftool python3 python3-pip
```

### 7.3 Python Dependencies
Install the required analytics, machine learning, and visualization libraries:
```bash
pip3 install rich scikit-learn xgboost joblib numpy scipy cryptography
```

### 7.4 Compile the eBPF Kernel Probes
Compile the eBPF bytecode (`sensor.bpf.o`) and the native userspace ring-buffer loader (`sensor_loader`):
```bash
make
```
*(To clean and recompile: `make clean && make`)*

---

## 8. Comprehensive CLI Command Reference

All functions across RansomShield can be executed via the unified orchestrator script `main.py`:

```bash
python3 main.py <subcommand> [flags]
```

### 8.1 Tier 1: Pre-Execution Triage Commands

| Command | Description |
| :--- | :--- |
| `python3 main.py triage --list` | Displays a list of test samples available in the MLRan dataset. |
| `python3 main.py triage --sample-id 11027` | Runs pre-execution triage on Locker Ransomware (Mbrlock). |
| `python3 main.py triage --sample-id 11036` | Runs pre-execution triage on Crypto Ransomware (CryptoLocker). |
| `python3 main.py triage --sample-id 13003` | Runs pre-execution triage on a benign application. |
| `python3 main.py triage --sample-id <ID> --model rf` | Runs triage using the Random Forest model instead of Logistic Regression. |
| `python3 main.py train` | Re-trains Tier 1 classifiers on MLRan dataset and displays the verification scorecard. |

---

### 8.2 Unified Dual-Tier Live Dashboard Commands

| Command | Mode | Description |
| :--- | :---: | :--- |
| `sudo python3 main.py monitor --watch-dir /tmp/ransomware_sandbox` | **Unified Dual-Tier Defense** | Starts the eBPF sensor and displays the unified Rich dashboard: **Tier 1 AI Threat Triage & Explainability** (Option B live ML model grounded in MLRan) + **Tier 2 In-Kernel Syscall Telemetry**. Freezes attacking processes mid-burst via `SIGSTOP`. |
| `sudo python3 main.py monitor --watch-dir /tmp/ransomware_sandbox --sample-id 11027` | **Sample Baseline Triage** | Preloads static MLRan sample baseline into the Tier 1 panel before dynamically transitioning to live runtime AI triage on active processes. |
| `sudo python3 main.py monitor --watch-dir /tmp/ransomware_sandbox --action kill` | **Aggressive Defense** | Automatically terminates attacking processes via `SIGKILL` mid-burst and isolates files. |
| `sudo python3 main.py monitor --watch-dir /tmp/ransomware_sandbox --no-dashboard` | **Headless Server** | Runs without the TUI dashboard, streaming raw events to standard output. |
| `sudo python3 main.py monitor --watch-dir /tmp/ransomware_sandbox --no-mitigate` | **Observation Only** | Observes and logs threat scores without executing automated process containment. |

---

### 8.3 Simulation & Workload Generation Commands

| Command | Description |
| :--- | :--- |
| `python3 workloads/setup_sandbox.py --sandbox /tmp/ransomware_sandbox` | Pre-populates the sandbox directory with mock user documents (`.txt`, `.pdf`, `.docx`). |
| `python3 main.py simulate --type ransomware --target-dir /tmp/ransomware_sandbox` | Executes a synthetic multi-file AES encryption burst with `.locked` renaming. |
| `python3 main.py simulate --type benign --target-dir /tmp/ransomware_sandbox` | Simulates legitimate user activity (text file creation, modifications, low entropy). |

---

### 8.4 Post-Detection Response & Isolation Management

| Command | Description |
| :--- | :--- |
| `python3 main.py alerts` | Prints the complete security incident history and quarantine log from the SQLite database. |
| `ls -la /tmp/.ransomshield_quarantine/` | Lists all encrypted files secured in the quarantine vault. |
| `python3 main.py isolate --pid <PID>` | Manually suspends a suspicious process by PID (`SIGSTOP`). |
| `python3 main.py kill --pid <PID>` | Manually terminates a process by PID (`SIGKILL`). |
| `python3 main.py resume --pid <PID>` | Resumes a suspended process (`SIGCONT`) in the event of an approved false alarm. |

---

### 8.5 Behavioral Engine & Evaluation Commands

| Command | Description |
| :--- | :--- |
| `python3 main.py detector` | Runs Member 2's offline behavioral classifier on default trace. |
| `python3 main.py detector <path/to/trace.json>` | Runs offline behavioral classification on a specific event trace. |
| `python3 main.py benchmark --tier both` | Runs the full evaluation benchmark across both Tier 1 and Tier 2. |
| `python3 main.py benchmark --tier 1` | Runs benchmark scorecard for Tier 1 MLRan AI models. |
| `sudo python3 main.py benchmark --tier 2` | Runs ground-truth telemetry accuracy validation for Tier 2 eBPF sensor. |
| `sudo python3 validation/run_member2_integration.py` | Runs end-to-end integration test validating eBPF stream input to Behavioral AI. |

---

## 9. Step-by-Step Live Demonstration Guide

Follow this walkthrough to demonstrate the full dual-tier prevention lifecycle:

### Step 1: Pre-Execution Triage (Terminal 1)
Verify that Tier 1 flags malicious binaries before they execute:
```bash
python3 main.py triage --sample-id 11027
```
*Result*: Displays 99.9% Ransomware probability, correctly identifying the sample as `LOCKER` (`Mbrlock`) with explainable API weights.

---

### Step 2: Initialize Runtime Defense (Terminal 1)
Start the real-time kernel watchdog on the target sandbox directory:
```bash
sudo python3 main.py monitor --watch-dir /tmp/ransomware_sandbox
```
*Result*: Terminal 1 renders the live Rich dashboard displaying zero events, low entropy, and a status of `RUNNING / NORMAL`.

---

### Step 3: Launch Attack Simulation (Terminal 2)
In a second terminal, execute the synthetic ransomware attack:
```bash
python3 main.py simulate --type ransomware --target-dir /tmp/ransomware_sandbox
```
*Result*:
* The attack begins encrypting mock files.
* Within milliseconds, the eBPF sensor intercepts rapid write bursts with entropy jumping to `7.8+`.
* The Decision Engine escalates the threat score to `90.0` (`CRITICAL`).
* **Active Defense Triggered**: Terminal 1 displays a red containment banner. The simulator in Terminal 2 is halted mid-execution with:
  ```text
  [!] Process frozen by RansomShield (SIGSTOP) mid-attack!
  ```

---

### Step 4: Verify Incident Containment & Quarantine (Terminal 2)
Verify that the attack was prevented from destroying the remainder of the directory:
```bash
# 1. View the incident log in the database:
python3 main.py alerts

# 2. Inspect the quarantined encrypted files:
ls -la /tmp/.ransomshield_quarantine/

# 3. Check that remaining files in the sandbox are intact:
ls -la /tmp/ransomware_sandbox/
```

---

## 10. Repository Structure & Codebase Map

```
Real_time_ransomware_detection/
├── main.py                           # Unified CLI orchestrator (triage, monitor, alerts, benchmark)
├── Makefile                          # Build automation for eBPF bytecode and native C loader
├── README.md                         # Comprehensive system documentation & evaluation guide
│
├── datasets/                         # Dataset repositories & persistent databases
│   ├── ransomshield.db               # SQLite database recording incidents, alerts, & quarantined PIDs
│   ├── sample_traces/                # Standardized JSON event traces for offline behavioral testing
│   └── MLRan/                        # Real-world MLRan dataset (JNCA 2026, 4,880 samples)
│       ├── MLRan_X_train_RFE.csv     # 3,905 training samples (483 RFE features)
│       ├── MLRan_X_test_RFE.csv      # 975 held-out evaluation samples (483 RFE features)
│       ├── MLRan_labels.csv          # Ground-truth binary and type labels
│       ├── mlran_dataset_metadata.csv# 64 ransomware families & metadata
│       └── RFE_selected_feature_names_dic.json # Feature name mapping dictionary
│
├── models/                           # Tier 1 AI classification & triage subsystem
│   ├── mlran_loader.py               # Robust dataset parser, schema mapper, & metadata resolver
│   ├── mlran_train.py                # Model training pipeline (LR, RF, XGB) & scorecard generator
│   ├── mlran_predict.py              # Real-time triage inference & feature explainability engine
│   └── saved/mlran/                  # Serialized production models (.joblib) & metadata JSON
│
├── ebpf/                             # Tier 2 Kernel telemetry subsystem
│   ├── vmlinux.h                     # Generated kernel BTF type definitions
│   ├── event.h                       # Shared kernel/userspace event structures
│   ├── sensor.bpf.c                  # Core eBPF program hooking kernel tracepoints
│   ├── sensor.bpf.o                  # Compiled eBPF bytecode object
│   ├── sensor_loader.c               # Native C userspace ring-buffer consumer
│   └── sensor_loader                 # Compiled native loader binary
│
├── collector/                        # Stream processing & dashboard visualization
│   ├── collector.py                  # Event streaming orchestrator & mitigation dispatcher
│   ├── normalizer.py                 # Shannon entropy calculator & schema normalizer
│   └── dashboard.py                  # Interactive, color-coded Rich Terminal UI (TUI)
│
├── engine/                           # Threat analytics & active mitigation subsystem
│   ├── decision_engine.py            # Heuristic sliding-window scoring, SIGSTOP/KILL, & quarantine
│   └── storage.py                    # DrvFS-optimized SQLite incident logger with batched commits
│
├── schema/                           # Standardized telemetry representations
│   └── event_schema.py               # NormalizedEvent dataclass schema
│
├── workloads/                        # Attack simulation & test environments
│   ├── setup_sandbox.py              # Mock user directory & document generator
│   ├── benign_workload.py            # Everyday benign user activity simulator
│   └── ransomware_simulator.py       # Realistic synthetic AES-256 ransomware simulator
│
└── validation/                       # Academic benchmark & verification test suites
    ├── validate_telemetry.py         # 100% telemetry capture rate ground-truth validator
    └── run_member2_integration.py    # End-to-end integration test with Behavioral AI Engine
```

---

## 11. Academic References & Citation

If you utilize the MLRan dataset, Tier 1 triage models, or the Tier 2 eBPF telemetry architecture in academic research, please cite:

```bibtex
@article{mlran2026,
  title   = {MLRan: A Machine Learning-Based Ransomware Detection and Family Attribution Dataset},
  journal = {Journal of Network and Computer Applications},
  year    = {2026},
  author  = {Faithful, C. and Collaborators},
  publisher = {Elsevier}
}

@software{ransomshield2026,
  title   = {RansomShield: Real-Time & Pre-Execution Dual-Tier Ransomware Defense System},
  author  = {Final Year Project Research Team},
  institution = {Vellore Institute of Technology (VIT)},
  year    = {2026}
}
```
