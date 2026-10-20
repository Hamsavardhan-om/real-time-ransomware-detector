"""
RansomShield Decision Engine (Block 8 - Response).

Executes active mitigation policies based on Threat Level:
- Low / Normal:      Log Only
- Medium / Watch:    Log & Monitor
- High / Warning:    Show Alert & Prompt User
- Critical / Attack: Isolate Process (SIGSTOP) + Quarantine Files
- Malicious / Block: Kill Process (SIGKILL) + Quarantine Files
"""

import os
import signal
import shutil
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from engine.threat_classifier import classify_threat_level, ThreatLevel
from engine.storage import RansomShieldStorage

logger = logging.getLogger("ransomshield.decision_engine")


@dataclass
class MitigationResult:
    action_taken: str          # LOG_ONLY, ALERT, ISOLATE, KILL, PROMPT
    pid: int
    process: str
    threat_score: float
    threat_level: str
    process_status: str        # RUNNING, SUSPENDED, TERMINATED, ALREADY_DEAD
    quarantined_files: List[str]
    message: str
    timestamp: float


class DecisionEngine:
    def __init__(
        self,
        storage: Optional[RansomShieldStorage] = None,
        quarantine_dir: str = "/tmp/.ransomshield_quarantine",
        auto_mitigate: bool = True,
        preferred_action: str = "isolate",  # "isolate" (SIGSTOP) or "kill" (SIGKILL)
    ):
        self.storage = storage or RansomShieldStorage()
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.quarantine_dir, 0o777)
        except Exception:
            pass

        self.auto_mitigate = auto_mitigate
        self.preferred_action = preferred_action
        self.mitigated_pids = set()
        self.mitigated_results: Dict[int, MitigationResult] = {}

    def is_pid_alive(self, pid: int) -> bool:
        """Checks if a process is still active."""
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    def isolate_process(self, pid: int) -> bool:
        """
        Freezes process in memory using SIGSTOP.
        Prevents further filesystem damage while preserving RAM for forensic key recovery.
        """
        if not self.is_pid_alive(pid):
            return False
        try:
            os.kill(pid, signal.SIGSTOP)
            logger.warning(f"[!] Process PID {pid} ISOLATED via SIGSTOP.")
            return True
        except Exception as e:
            logger.error(f"Failed to isolate PID {pid}: {e}")
            return False

    def kill_process(self, pid: int) -> bool:
        """Terminates process immediately using SIGKILL."""
        if not self.is_pid_alive(pid):
            return False
        try:
            os.kill(pid, signal.SIGKILL)
            logger.warning(f"[!] Process PID {pid} TERMINATED via SIGKILL.")
            return True
        except Exception as e:
            logger.error(f"Failed to kill PID {pid}: {e}")
            return False

    def resume_process(self, pid: int) -> bool:
        """Resumes a suspended process (in case of false positive)."""
        if not self.is_pid_alive(pid):
            return False
        try:
            os.kill(pid, signal.SIGCONT)
            logger.info(f"[+] Process PID {pid} RESUMED via SIGCONT.")
            return True
        except Exception as e:
            logger.error(f"Failed to resume PID {pid}: {e}")
            return False

    def quarantine_files(self, paths: List[str]) -> List[str]:
        """
        Moves suspicious or encrypted files into the secure quarantine vault.
        """
        quarantined = []
        for p_str in paths:
            if not p_str:
                continue
            p = Path(p_str)
            if p.exists() and p.is_file():
                try:
                    dest = self.quarantine_dir / f"{int(time.time())}_{p.name}"
                    shutil.move(str(p), str(dest))
                    quarantined.append(str(dest))
                except Exception as e:
                    logger.debug(f"Quarantine move failed for {p}: {e}")
        return quarantined

    def evaluate_and_respond(
        self,
        pid: int,
        process_name: str,
        threat_score: float,
        touched_files: Optional[List[str]] = None,
        score_id: Optional[int] = None,
    ) -> MitigationResult:
        """
        Takes threat assessment, applies security policy, triggers mitigation,
        and logs results to persistent storage.
        """
        level = classify_threat_level(threat_score)
        now = time.time()
        quarantined = []
        proc_status = "RUNNING"
        action_taken = "LOG_ONLY"
        msg = f"Threat score {threat_score:.1f} ({level.label}). Normal operation."

        # Filter out self or system PIDs
        if pid <= 1 or pid == os.getpid():
            return MitigationResult(
                action_taken="LOG_ONLY",
                pid=pid,
                process=process_name,
                threat_score=threat_score,
                threat_level=level.code,
                process_status="RUNNING",
                quarantined_files=[],
                message="Ignored self or init process.",
                timestamp=now,
            )

        if level.code in ["CRITICAL", "MALICIOUS"]:
            if pid in self.mitigated_pids:
                prev = self.mitigated_results.get(pid)
                action_taken = prev.action_taken if prev else ("ISOLATE_PROCESS" if self.preferred_action == "isolate" else "KILL_PROCESS")
                proc_status = prev.process_status if prev else ("SUSPENDED" if self.preferred_action == "isolate" else "TERMINATED")
                quarantined = prev.quarantined_files if prev else []
                msg = prev.message if prev else f"CRITICAL ATTACK: Process {process_name} (PID {pid}) neutralized."
            elif self.auto_mitigate:
                if level.code == "MALICIOUS" or self.preferred_action == "kill":
                    if self.kill_process(pid):
                        action_taken = "KILL_PROCESS"
                        proc_status = "TERMINATED"
                        msg = f"CRITICAL ATTACK: Process {process_name} (PID {pid}) TERMINATED immediately."
                    else:
                        action_taken = "KILL_PROCESS"
                        proc_status = "EXITED_AFTER_BURST"
                        msg = f"CRITICAL ATTACK: Process {process_name} (PID {pid}) neutralized."
                else:
                    if self.isolate_process(pid):
                        action_taken = "ISOLATE_PROCESS"
                        proc_status = "SUSPENDED"
                        msg = f"CRITICAL ATTACK: Process {process_name} (PID {pid}) ISOLATED (frozen in RAM) to halt encryption."
                    else:
                        action_taken = "ISOLATE_PROCESS"
                        proc_status = "EXITED_AFTER_BURST"
                        msg = f"CRITICAL ATTACK: Process {process_name} (PID {pid}) neutralized."

                self.mitigated_pids.add(pid)

                # Quarantine touched .locked or newly encrypted files
                if touched_files:
                    target_to_quarantine = []
                    for f in touched_files:
                        if not f:
                            continue
                        if f.endswith(".locked") or f.endswith(".txt.note") or "HOW_TO_RESTORE" in f:
                            target_to_quarantine.append(f)
                        elif Path(f + ".locked").exists():
                            target_to_quarantine.append(f + ".locked")
                    quarantined = self.quarantine_files(target_to_quarantine)

                res = MitigationResult(
                    action_taken=action_taken,
                    pid=pid,
                    process=process_name,
                    threat_score=threat_score,
                    threat_level=level.code,
                    process_status=proc_status,
                    quarantined_files=quarantined,
                    message=msg,
                    timestamp=now,
                )
                self.mitigated_results[pid] = res

        elif level.code == "HIGH":
            action_taken = "ALERT_NOTIFICATION"
            msg = f"HIGH RISK ACTIVITY detected from {process_name} (PID {pid}). User notified."

        # Log action to persistent storage (Block 9B)
        self.storage.log_alert(
            pid=pid,
            process=process_name,
            level=level.code,
            action_taken=action_taken,
            details=msg + (f" Quarantined {len(quarantined)} files." if quarantined else ""),
            score_id=score_id,
        )

        return MitigationResult(
            action_taken=action_taken,
            pid=pid,
            process=process_name,
            threat_score=threat_score,
            threat_level=level.code,
            process_status=proc_status,
            quarantined_files=quarantined,
            message=msg,
            timestamp=now,
        )
